defmodule ConfigManager.Forwarding.ContextTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Forwarding
  alias ConfigManager.Forwarding.{ForwardingSink, SinkSecret}
  alias ConfigManager.{AuditEntry, Pools, Repo, SensorPool}

  setup do
    previous = System.get_env("RAVENWIRE_SINK_ENCRYPTION_KEY")
    System.put_env("RAVENWIRE_SINK_ENCRYPTION_KEY", Base.encode64(:crypto.strong_rand_bytes(32)))
    {:ok, supervisor} = Task.Supervisor.start_link()

    on_exit(fn ->
      Process.exit(supervisor, :shutdown)

      if previous do
        System.put_env("RAVENWIRE_SINK_ENCRYPTION_KEY", previous)
      else
        System.delete_env("RAVENWIRE_SINK_ENCRYPTION_KEY")
      end
    end)

    {:ok, supervisor: supervisor}
  end

  test "creates sinks with encrypted secrets, sanitized config, audit, and version increment" do
    {:ok, pool} = Pools.create_pool(%{"name" => unique_name("forwarding-create")}, "tester")

    assert {:ok, sink} =
             Forwarding.create_sink(
               pool.id,
               %{
                 "name" => "Splunk",
                 "sink_type" => "splunk_hec",
                 "endpoint" => "https://splunk.example",
                 "hec_token" => "super-secret-token",
                 "index" => "main"
               },
               "operator"
             )

    assert sink.name == "Splunk"
    assert sink.normalized_name == "splunk"
    assert sink.enabled
    assert sink.config =~ "splunk.example"
    refute sink.config =~ "super-secret-token"

    secret = Repo.get_by!(SinkSecret, forwarding_sink_id: sink.id, secret_name: "hec_token")
    assert secret.last_four == "oken"
    refute secret.ciphertext =~ "super-secret-token"

    reloaded_pool = Repo.get!(SensorPool, pool.id)
    assert reloaded_pool.forwarding_config_version == 1
    assert reloaded_pool.forwarding_config_updated_by == "operator"

    audit = Repo.get_by!(AuditEntry, action: "sink_created", target_id: sink.id)
    assert audit.actor == "operator"
    refute audit.detail =~ "super-secret-token"
  end

  test "updates sinks while preserving unchanged secrets" do
    {:ok, pool} = Pools.create_pool(%{"name" => unique_name("forwarding-update")}, "tester")
    {:ok, sink} = create_file_sink(pool.id, "file-a")

    assert {:ok, updated} =
             Forwarding.update_sink(
               pool.id,
               sink.id,
               %{
                 "name" => "file-b",
                 "path_template" => "/var/log/ravenwire/%Y/%m/events.ndjson",
                 "encoding" => "ndjson"
               },
               "operator"
             )

    assert updated.name == "file-b"
    assert Repo.get!(SensorPool, pool.id).forwarding_config_version == 2

    {:ok, splunk} =
      Forwarding.create_sink(
        pool.id,
        %{
          "name" => "splunk-preserve",
          "sink_type" => "splunk_hec",
          "endpoint" => "https://splunk.example",
          "hec_token" => "original-token"
        },
        "operator"
      )

    before_secret =
      Repo.get_by!(SinkSecret, forwarding_sink_id: splunk.id, secret_name: "hec_token")

    assert {:ok, _updated} =
             Forwarding.update_sink(
               pool.id,
               splunk.id,
               %{
                 "name" => "splunk-preserve",
                 "endpoint" => "https://splunk2.example",
                 "hec_token" => "********"
               },
               "operator"
             )

    after_secret = Repo.get!(SinkSecret, before_secret.id)
    assert after_secret.ciphertext == before_secret.ciphertext
    assert after_secret.last_four == before_secret.last_four
  end

  test "toggle, schema mode, and delete update forwarding version without leaking details" do
    {:ok, pool} = Pools.create_pool(%{"name" => unique_name("forwarding-lifecycle")}, "tester")
    {:ok, sink} = create_file_sink(pool.id, "file-toggle")

    assert {:ok, disabled} = Forwarding.toggle_sink(pool.id, sink.id, "operator")
    refute disabled.enabled
    assert Repo.get!(SensorPool, pool.id).forwarding_config_version == 2

    assert {:ok, mode_pool} = Forwarding.update_schema_mode(pool.id, "ecs", "operator")
    assert mode_pool.schema_mode == "ecs"
    assert mode_pool.forwarding_config_version == 3

    assert {:ok, deleted} = Forwarding.delete_sink(pool.id, sink.id, "operator")
    assert deleted.id == sink.id
    assert Repo.get(ForwardingSink, sink.id) == nil
    assert Repo.get!(SensorPool, pool.id).forwarding_config_version == 4
  end

  test "forwarding summary and deployment snapshot include secret-safe forwarding state" do
    {:ok, pool} = Pools.create_pool(%{"name" => unique_name("forwarding-summary")}, "tester")
    {:ok, _sink} = create_file_sink(pool.id, "file-summary")

    summary = Forwarding.forwarding_summary(pool.id)
    assert summary.sink_count == 1
    assert summary.enabled_count == 1
    assert summary.schema_mode == "raw"
  end

  test "test_connection stores sanitized result and audit without incrementing forwarding version",
       %{supervisor: supervisor} do
    {:ok, pool} = Pools.create_pool(%{"name" => unique_name("forwarding-test")}, "tester")
    {:ok, sink} = create_http_sink(pool.id, "http-test")
    sink_id = sink.id
    version_before = Repo.get!(SensorPool, pool.id).forwarding_config_version

    assert :ok =
             Forwarding.test_connection(pool.id, sink.id, self(),
               actor: "operator",
               supervisor: supervisor,
               tester: fn _sink ->
                 %{
                   success: false,
                   message:
                     "failed for https://user:pass@example.test/path?token=secret password=hunter2",
                   error_category: "auth",
                   endpoint: "https://user:pass@example.test/path?token=secret"
                 }
               end
             )

    assert_receive {:connection_test_result, ^sink_id, result}, 500
    refute result.success
    refute inspect(result) =~ "hunter2"
    refute inspect(result) =~ "token=secret"
    refute inspect(result) =~ "user:pass"

    persisted = Repo.get!(ForwardingSink, sink.id)
    decoded = Jason.decode!(persisted.last_test_result)
    assert decoded["success"] == false
    assert decoded["error_category"] == "auth"
    refute persisted.last_test_result =~ "hunter2"
    refute persisted.last_test_result =~ "token=secret"

    assert Repo.get!(SensorPool, pool.id).forwarding_config_version == version_before

    audit = Repo.get_by!(AuditEntry, action: "sink_connection_tested", target_id: sink.id)
    assert audit.actor == "operator"
    assert audit.detail =~ "auth"
    refute audit.detail =~ "hunter2"
    refute audit.detail =~ "token=secret"
  end

  test "test_connection rejects cross-pool sink access", %{supervisor: supervisor} do
    {:ok, pool_a} = Pools.create_pool(%{"name" => unique_name("forwarding-pool-a")}, "tester")
    {:ok, pool_b} = Pools.create_pool(%{"name" => unique_name("forwarding-pool-b")}, "tester")
    {:ok, sink} = create_http_sink(pool_a.id, "http-cross-pool")

    assert {:error, :not_found} =
             Forwarding.test_connection(pool_b.id, sink.id, self(),
               actor: "operator",
               supervisor: supervisor,
               tester: fn _sink -> flunk("cross-pool sink should not be tested") end
             )
  end

  defp create_file_sink(pool_id, name) do
    Forwarding.create_sink(
      pool_id,
      %{
        "name" => name,
        "sink_type" => "file",
        "path_template" => "/var/log/ravenwire/events.ndjson",
        "encoding" => "ndjson"
      },
      "operator"
    )
  end

  defp create_http_sink(pool_id, name) do
    Forwarding.create_sink(
      pool_id,
      %{
        "name" => name,
        "sink_type" => "http",
        "endpoint" => "https://8.8.8.8/collect",
        "method" => "POST",
        "auth_type" => "none"
      },
      "operator"
    )
  end

  defp unique_name(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"
end
