defmodule ConfigManager.Bpf.ContextTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Bpf
  alias ConfigManager.Bpf.BpfProfile
  alias ConfigManager.{AuditEntry, Repo, SensorPod, SensorPool}
  alias ConfigManager.Health.Registry

  test "create_profile initializes defaults, version snapshot, audit, and PubSub" do
    pool = insert_pool!("bpf-create")
    pool_id = pool.id
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool_id}:bpf")

    assert {:ok, profile} = Bpf.create_profile(pool.id, "tester")
    assert_receive {:bpf_profile_created, ^pool_id}

    assert profile.pool_id == pool.id
    assert profile.version == 1
    assert profile.composition_mode == "append"
    assert profile.raw_expression == nil
    assert profile.compiled_expression == nil
    assert Bpf.list_rules(profile.id) == []

    version = Bpf.get_version(profile.id, 1)
    assert version.rules_snapshot == []
    assert version.created_by == "tester"

    audit = Repo.get_by!(AuditEntry, action: "bpf_profile_created", target_id: profile.id)
    assert audit.actor == "tester"
    assert Jason.decode!(audit.detail)["compiled_expression"] == nil

    assert {:error, :profile_exists} = Bpf.create_profile(pool.id, "tester")
  end

  test "save_profile compiles changed configuration, stores rules, snapshots, audit, and summary" do
    pool = insert_pool!("bpf-save")
    pool_id = pool.id
    {:ok, profile} = Bpf.create_profile(pool.id, "tester")
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool_id}:bpf")

    params = %{
      rules: [
        %{
          rule_type: "port_exclusion",
          params: %{"port" => "443", "protocol" => "tcp"},
          label: "tls",
          enabled: true,
          position: 1
        },
        %{
          rule_type: "cidr_pair",
          params: %{"src_cidr" => "10.0.0.0/8", "dst_cidr" => "192.168.0.0/16"},
          enabled: true,
          position: 0
        }
      ],
      raw_expression: " tcp ",
      composition_mode: "append"
    }

    test_pid = self()

    compiler = fn expression ->
      send(test_pid, {:compiled_expression, expression})
      {:ok, %{instruction_count: 4}}
    end

    assert {:ok, updated} = Bpf.save_profile(profile, params, "tester", compiler: compiler)
    assert_receive {:bpf_profile_updated, ^pool_id}
    assert_receive {:compiled_expression, compiled_expression}

    assert updated.version == 2
    assert updated.raw_expression == "tcp"
    assert updated.compiled_expression == compiled_expression
    assert updated.updated_by == "tester"

    rules = Bpf.list_rules(profile.id)
    assert Enum.map(rules, & &1.position) == [0, 1]
    assert Enum.map(rules, & &1.rule_type) == ["cidr_pair", "port_exclusion"]

    version = Bpf.get_version(profile.id, 2)
    assert version.compiled_expression == compiled_expression
    assert length(version.rules_snapshot) == 2

    audit = Repo.get_by!(AuditEntry, action: "bpf_profile_updated", target_id: profile.id)
    detail = Jason.decode!(audit.detail)
    assert detail["old_version"] == 1
    assert detail["new_version"] == 2
    assert detail["compiled_expression"] == compiled_expression

    assert Bpf.bpf_summary(pool.id) == %{
             has_profile: true,
             version: 2,
             last_deployed_version: nil,
             enabled_rule_count: 2,
             total_rule_count: 2,
             has_raw_expression: true,
             composition_mode: "append",
             pending_deployment: true,
             updated_at: updated.updated_at,
             updated_by: "tester"
           }

    assert {:ok, unchanged} =
             Bpf.save_profile(updated, params, "tester", compiler: fn _ -> flunk("unchanged") end)

    assert unchanged.version == 2
    assert Enum.map(Bpf.list_versions(profile.id), & &1.version) == [2, 1]
  end

  test "save_profile returns compilation errors without mutating persisted state" do
    pool = insert_pool!("bpf-compile-failure")
    {:ok, profile} = Bpf.create_profile(pool.id, "tester")

    params = %{
      rules: [%{rule_type: "port_exclusion", params: %{"port" => 53}, position: 0}],
      raw_expression: nil,
      composition_mode: "append"
    }

    assert {:error, {:compilation_failed, %{message: "invalid bpf"}}} =
             Bpf.save_profile(profile, params, "tester",
               compiler: fn _expression -> {:error, %{message: "invalid bpf"}} end
             )

    persisted = Repo.get!(BpfProfile, profile.id)
    assert persisted.version == 1
    assert persisted.compiled_expression == nil
    assert Bpf.list_rules(profile.id) == []
    assert Bpf.get_version(profile.id, 2) == nil
  end

  test "reset_profile clears rules and expressions, increments version, snapshots, audits, and broadcasts" do
    pool = insert_pool!("bpf-reset")
    pool_id = pool.id
    {:ok, profile} = Bpf.create_profile(pool.id, "tester")

    {:ok, updated} =
      Bpf.save_profile(
        profile,
        %{
          rules: [%{rule_type: "port_exclusion", params: %{"port" => 443}, position: 0}],
          raw_expression: "tcp",
          composition_mode: "append"
        },
        "tester",
        compiler: fn _expression -> {:ok, %{instruction_count: 2}} end
      )

    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool_id}:bpf")

    assert {:ok, reset} = Bpf.reset_profile(updated, "operator")
    assert_receive {:bpf_profile_reset, ^pool_id}

    assert reset.version == 3
    assert reset.raw_expression == nil
    assert reset.composition_mode == "append"
    assert reset.compiled_expression == nil
    assert reset.updated_by == "operator"
    assert Bpf.list_rules(profile.id) == []

    version = Bpf.get_version(profile.id, 3)
    assert version.rules_snapshot == []
    assert version.created_by == "operator"

    audit = Repo.get_by!(AuditEntry, action: "bpf_profile_reset", target_id: profile.id)
    detail = Jason.decode!(audit.detail)
    assert detail["old_version"] == 2
    assert detail["new_version"] == 3
  end

  test "bpf_summary handles pools without profiles and restart pending sensors use Health Registry" do
    pool = insert_pool!("bpf-summary")
    pending = insert_sensor!("pending-bpf", pool.id)
    clear = insert_sensor!("clear-bpf", pool.id)

    assert Bpf.bpf_summary(pool.id).has_profile == false
    assert Bpf.bpf_restart_pending_sensors(pool.id) == %{count: 0, sensors: []}

    Registry.update(pending.name, %Health.HealthReport{
      sensor_pod_id: pending.name,
      capture: %Health.CaptureStats{
        consumers: %{
          "main" => %Health.ConsumerStats{bpf_restart_pending: true}
        }
      }
    })

    Registry.update(clear.name, %Health.HealthReport{
      sensor_pod_id: clear.name,
      capture: %Health.CaptureStats{
        consumers: %{
          "main" => %Health.ConsumerStats{bpf_restart_pending: false}
        }
      }
    })

    assert Bpf.bpf_restart_pending_sensors(pool.id) == %{
             count: 1,
             sensors: [%{id: pending.id, name: pending.name}]
           }
  end

  defp insert_pool!(prefix) do
    name = "#{prefix}-#{System.unique_integer([:positive])}"

    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "tester")
    |> Repo.insert!()
  end

  defp insert_sensor!(prefix, pool_id) do
    name = "#{prefix}-#{System.unique_integer([:positive])}"

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "tester"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end
end
