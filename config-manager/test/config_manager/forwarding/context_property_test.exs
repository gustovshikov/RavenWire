defmodule ConfigManager.Forwarding.ContextPropertyTest do
  use ConfigManager.DataCase, async: false
  use PropCheck

  import Ecto.Query

  alias ConfigManager.Forwarding
  alias ConfigManager.Forwarding.{ForwardingSink, SinkSecret}
  alias ConfigManager.{AuditEntry, Pools, Repo, SensorPool}

  @cross_pool_failure_actions ~w(sink_updated sink_deleted sink_toggled sink_connection_tested)
  @audit_success_actions ~w(
    sink_created
    sink_updated
    sink_deleted
    sink_toggled
    schema_mode_changed
    sink_connection_tested
  )

  setup do
    previous = System.get_env("RAVENWIRE_SINK_ENCRYPTION_KEY")
    System.put_env("RAVENWIRE_SINK_ENCRYPTION_KEY", Base.encode64(:crypto.strong_rand_bytes(32)))
    {:ok, supervisor} = Task.Supervisor.start_link()
    Process.put(:forwarding_property_supervisor, supervisor)

    on_exit(fn ->
      Process.exit(supervisor, :shutdown)

      if previous do
        System.put_env("RAVENWIRE_SINK_ENCRYPTION_KEY", previous)
      else
        System.delete_env("RAVENWIRE_SINK_ENCRYPTION_KEY")
      end
    end)

    :ok
  end

  property "Property 2: Case-insensitive sink name uniqueness within a pool",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      {:ok, pool_a} =
        Pools.create_pool(%{"name" => unique_name("forwarding-name-a-#{code}")}, "property")

      {:ok, pool_b} =
        Pools.create_pool(%{"name" => unique_name("forwarding-name-b-#{code}")}, "property")

      name = "Sink_#{code}"

      {:ok, _sink} = create_file_sink(pool_a.id, name)
      duplicate = Forwarding.create_sink(pool_a.id, file_attrs(String.downcase(name)), "property")
      other_pool = Forwarding.create_sink(pool_b.id, file_attrs(String.upcase(name)), "property")

      same_pool_count =
        Repo.aggregate(from(s in ForwardingSink, where: s.pool_id == ^pool_a.id), :count, :id)

      match?({:error, %Ecto.Changeset{}}, duplicate) and
        match?({:ok, %ForwardingSink{}}, other_pool) and
        same_pool_count == 1
    end
  end

  property "Property 13: Schema mode validation against allowed set",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 1_000) do
      mode = schema_mode_case(code)
      pool = %SensorPool{schema_mode: "raw", forwarding_config_version: 0}
      changeset = SensorPool.schema_mode_changeset(pool, %{schema_mode: mode}, "property")

      changeset.valid? == mode in SensorPool.valid_schema_modes()
    end
  end

  property "Property 10: Pool cascade deletes all associated sinks and secrets",
           [:verbose, numtests: 30] do
    forall code <- integer(1, 10_000) do
      {:ok, pool} =
        Pools.create_pool(%{"name" => unique_name("forwarding-cascade-#{code}")}, "property")

      {:ok, other_pool} =
        Pools.create_pool(
          %{"name" => unique_name("forwarding-cascade-other-#{code}")},
          "property"
        )

      {:ok, splunk_sink} = create_splunk_sink(pool.id, "splunk-#{code}")
      {:ok, file_sink} = create_file_sink(pool.id, "file-cascade-#{code}")
      {:ok, other_sink} = create_splunk_sink(other_pool.id, "splunk-other-#{code}")

      Repo.delete!(pool)

      Repo.get(ForwardingSink, splunk_sink.id) == nil and
        Repo.get(ForwardingSink, file_sink.id) == nil and
        Repo.aggregate(
          from(s in ConfigManager.Forwarding.SinkSecret,
            where: s.forwarding_sink_id in ^[splunk_sink.id, file_sink.id]
          ),
          :count,
          :id
        ) == 0 and
        Repo.get(ForwardingSink, other_sink.id) != nil and
        Repo.exists?(
          from(s in ConfigManager.Forwarding.SinkSecret,
            where: s.forwarding_sink_id == ^other_sink.id
          )
        )
    end
  end

  property "Property 5: Forwarding_Config_Version increments exactly on configuration changes",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      {:ok, pool} =
        Pools.create_pool(%{"name" => unique_name("forwarding-version-#{code}")}, "property")

      operations = version_operations(code)
      initial = %{pool_id: pool.id, sink: nil, expected_version: 0, code: code, step: 0}

      final =
        Enum.reduce_while(operations, initial, fn operation, state ->
          case apply_version_operation(operation, state) do
            {:ok, next_state} ->
              if persisted_forwarding_version(pool.id) == next_state.expected_version do
                {:cont, next_state}
              else
                {:halt, Map.put(next_state, :version_mismatch?, true)}
              end

            {:error, reason} ->
              {:halt, state |> Map.put(:operation_error, {operation, reason})}
          end
        end)

      not Map.get(final, :version_mismatch?, false) and
        not Map.has_key?(final, :operation_error)
    end
  end

  property "Property 6: Cross-pool sink access denial",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      {:ok, pool_a} =
        Pools.create_pool(%{"name" => unique_name("forwarding-cross-a-#{code}")}, "property")

      {:ok, pool_b} =
        Pools.create_pool(%{"name" => unique_name("forwarding-cross-b-#{code}")}, "property")

      {:ok, sink} = create_file_sink(pool_a.id, "file-cross-#{code}")
      version_a = persisted_forwarding_version(pool_a.id)
      version_b = persisted_forwarding_version(pool_b.id)

      read_denied? = Forwarding.get_sink_for_pool(pool_b.id, sink.id) == {:error, :not_found}

      update_denied? =
        Forwarding.update_sink(
          pool_b.id,
          sink.id,
          file_attrs("file-cross-updated-#{code}"),
          "property"
        ) ==
          {:error, :not_found}

      toggle_denied? =
        Forwarding.toggle_sink(pool_b.id, sink.id, "property") == {:error, :not_found}

      test_denied? =
        Forwarding.test_connection(pool_b.id, sink.id, self(),
          actor: "property",
          supervisor: Process.get(:forwarding_property_supervisor),
          tester: fn _sink -> flunk("cross-pool sink should not be tested") end
        ) == {:error, :not_found}

      delete_denied? =
        Forwarding.delete_sink(pool_b.id, sink.id, "property") == {:error, :not_found}

      persisted = Repo.get!(ForwardingSink, sink.id)

      read_denied? and update_denied? and toggle_denied? and test_denied? and delete_denied? and
        persisted.pool_id == pool_a.id and
        persisted.enabled == sink.enabled and
        persisted_forwarding_version(pool_a.id) == version_a and
        persisted_forwarding_version(pool_b.id) == version_b and
        cross_pool_failure_audit_count(sink.id) == 4
    end
  end

  property "Property 11: Secret preservation on unchanged edit",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      {:ok, pool} =
        Pools.create_pool(%{"name" => unique_name("forwarding-secret-#{code}")}, "property")

      {:ok, sink} = create_splunk_sink(pool.id, "splunk-secret-#{code}")
      before_secret = secret!(sink.id, "hec_token")

      {:ok, updated} =
        Forwarding.update_sink(
          pool.id,
          sink.id,
          %{
            "name" => "splunk-secret-updated-#{code}",
            "endpoint" => "https://splunk-#{code}.example",
            "index" => "main-#{rem(code, 10)}",
            "hec_token" => "********"
          },
          "property"
        )

      after_secret = Repo.get!(SinkSecret, before_secret.id)

      updated.name == "splunk-secret-updated-#{code}" and
        updated.config =~ "splunk-#{code}.example" and
        after_secret.forwarding_sink_id == before_secret.forwarding_sink_id and
        after_secret.secret_name == before_secret.secret_name and
        after_secret.ciphertext == before_secret.ciphertext and
        after_secret.last_four == before_secret.last_four and
        after_secret.updated_at == before_secret.updated_at
    end
  end

  property "Property 8: Transactional audit integrity",
           [:verbose, numtests: 30] do
    forall code <- integer(1, 100_000) do
      case rem(code, 5) do
        0 -> create_rolls_back_on_audit_failure?(code)
        1 -> update_rolls_back_on_audit_failure?(code)
        2 -> delete_rolls_back_on_audit_failure?(code)
        3 -> toggle_rolls_back_on_audit_failure?(code)
        4 -> schema_mode_rolls_back_on_audit_failure?(code)
      end
    end
  end

  property "Property 7: Audit entry completeness and sanitization",
           [:verbose, numtests: 30] do
    forall code <- integer(1, 100_000) do
      case rem(code, 6) do
        0 -> create_audit_complete_and_safe?(code)
        1 -> update_audit_complete_and_safe?(code)
        2 -> delete_audit_complete_and_safe?(code)
        3 -> toggle_audit_complete_and_safe?(code)
        4 -> schema_audit_complete_and_safe?(code)
        5 -> connection_audit_complete_and_safe?(code)
      end
    end
  end

  property "Property 4: Secrets never leak to responses, audit entries, or PubSub",
           [:verbose, numtests: 30] do
    forall code <- integer(1, 100_000) do
      secret = "pubsub-secret-#{code}-#{System.unique_integer([:positive])}"

      {:ok, pool} =
        Pools.create_pool(%{"name" => unique_name("forwarding-secret-leak-#{code}")}, "property")

      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}:forwarding")

      {:ok, created} =
        Forwarding.create_sink(
          pool.id,
          splunk_create_attrs("splunk-leak-#{code}", secret),
          "property"
        )

      {:sink_created, created_payload} = receive_forwarding_message(:sink_created, created.id)

      rotated_secret = "rotated-#{secret}"

      {:ok, updated} =
        Forwarding.update_sink(
          pool.id,
          created.id,
          splunk_attrs("splunk-leak-updated-#{code}", rotated_secret),
          "property"
        )

      {:sink_updated, updated_payload} = receive_forwarding_message(:sink_updated, updated.id)

      {:ok, toggled} = Forwarding.toggle_sink(pool.id, created.id, "property")
      {:sink_toggled, toggled_payload} = receive_forwarding_message(:sink_toggled, toggled.id)

      {:ok, _pool} = Forwarding.update_schema_mode(pool.id, "ecs", "property")

      {:schema_mode_changed, schema_payload} =
        receive_forwarding_message(:schema_mode_changed, nil)

      audits_safe? =
        Repo.all(from(a in AuditEntry, where: a.result == "success"))
        |> Enum.all?(&(not contains_any_secret?(&1, [secret, rotated_secret])))

      persisted = Repo.get!(ForwardingSink, created.id)

      not contains_any_secret?(created, [secret, rotated_secret]) and
        not contains_any_secret?(updated, [secret, rotated_secret]) and
        not contains_any_secret?(toggled, [secret, rotated_secret]) and
        not contains_any_secret?(created_payload, [secret, rotated_secret]) and
        not contains_any_secret?(updated_payload, [secret, rotated_secret]) and
        not contains_any_secret?(toggled_payload, [secret, rotated_secret]) and
        not contains_any_secret?(schema_payload, [secret, rotated_secret]) and
        not contains_any_secret?(persisted.config, [secret, rotated_secret]) and
        audits_safe?
    end
  end

  defp create_rolls_back_on_audit_failure?(code) do
    {:ok, pool} =
      Pools.create_pool(%{"name" => unique_name("forwarding-audit-create-#{code}")}, "property")

    version = persisted_forwarding_version(pool.id)

    result =
      Forwarding.create_sink(pool.id, file_attrs("audit-fail-create-#{code}"), %{username: nil})

    not match?({:ok, _sink}, result) and
      Forwarding.list_sinks(pool.id) == [] and
      persisted_forwarding_version(pool.id) == version
  end

  defp update_rolls_back_on_audit_failure?(code) do
    {:ok, pool} =
      Pools.create_pool(%{"name" => unique_name("forwarding-audit-update-#{code}")}, "property")

    {:ok, sink} = create_splunk_sink(pool.id, "splunk-audit-update-#{code}")
    version = persisted_forwarding_version(pool.id)
    before_sink = Repo.get!(ForwardingSink, sink.id)
    before_secret = secret!(sink.id, "hec_token")

    result =
      Forwarding.update_sink(
        pool.id,
        sink.id,
        splunk_attrs("splunk-audit-updated-#{code}", "rotated-token-#{code}"),
        %{username: nil}
      )

    after_sink = Repo.get!(ForwardingSink, sink.id)
    after_secret = secret!(sink.id, "hec_token")

    not match?({:ok, _sink}, result) and
      sink_state(after_sink) == sink_state(before_sink) and
      secret_state(after_secret) == secret_state(before_secret) and
      persisted_forwarding_version(pool.id) == version
  end

  defp delete_rolls_back_on_audit_failure?(code) do
    {:ok, pool} =
      Pools.create_pool(%{"name" => unique_name("forwarding-audit-delete-#{code}")}, "property")

    {:ok, sink} = create_splunk_sink(pool.id, "splunk-audit-delete-#{code}")
    version = persisted_forwarding_version(pool.id)
    before_secret = secret!(sink.id, "hec_token")

    result = Forwarding.delete_sink(pool.id, sink.id, %{username: nil})

    after_sink = Repo.get!(ForwardingSink, sink.id)
    after_secret = secret!(sink.id, "hec_token")

    not match?({:ok, _sink}, result) and
      after_sink.id == sink.id and
      secret_state(after_secret) == secret_state(before_secret) and
      persisted_forwarding_version(pool.id) == version
  end

  defp toggle_rolls_back_on_audit_failure?(code) do
    {:ok, pool} =
      Pools.create_pool(%{"name" => unique_name("forwarding-audit-toggle-#{code}")}, "property")

    {:ok, sink} = create_file_sink(pool.id, "file-audit-toggle-#{code}")
    version = persisted_forwarding_version(pool.id)

    result = Forwarding.toggle_sink(pool.id, sink.id, %{username: nil})
    persisted = Repo.get!(ForwardingSink, sink.id)

    not match?({:ok, _sink}, result) and
      persisted.enabled == sink.enabled and
      persisted_forwarding_version(pool.id) == version
  end

  defp schema_mode_rolls_back_on_audit_failure?(code) do
    {:ok, pool} =
      Pools.create_pool(%{"name" => unique_name("forwarding-audit-schema-#{code}")}, "property")

    version = persisted_forwarding_version(pool.id)

    result = Forwarding.update_schema_mode(pool.id, "ecs", %{username: nil})
    persisted = Repo.get!(SensorPool, pool.id)

    not match?({:ok, _pool}, result) and
      persisted.schema_mode == pool.schema_mode and
      persisted_forwarding_version(pool.id) == version
  end

  defp create_audit_complete_and_safe?(code) do
    secret = "audit-create-secret-#{code}"

    {:ok, pool} =
      Pools.create_pool(
        %{"name" => unique_name("forwarding-audit-ok-create-#{code}")},
        "property"
      )

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        splunk_create_attrs("splunk-audit-ok-#{code}", secret),
        "auditor"
      )

    audit = audit_entry!("sink_created", sink.id)
    detail = decoded_detail(audit)

    valid_success_audit?(audit, "auditor", "sink_created", "forwarding_sink", sink.id) and
      detail["name"] == sink.name and
      detail["sink_type"] == "splunk_hec" and
      detail["pool_id"] == pool.id and
      detail["pool_name"] == pool.name and
      detail["secrets_present"] == ["hec_token"] and
      not contains_any_secret?(audit, [secret])
  end

  defp update_audit_complete_and_safe?(code) do
    old_secret = "audit-update-old-secret-#{code}"
    new_secret = "audit-update-new-secret-#{code}"

    {:ok, pool} =
      Pools.create_pool(
        %{"name" => unique_name("forwarding-audit-ok-update-#{code}")},
        "property"
      )

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        splunk_create_attrs("splunk-audit-update-#{code}", old_secret),
        "auditor"
      )

    {:ok, updated} =
      Forwarding.update_sink(
        pool.id,
        sink.id,
        splunk_attrs("splunk-audit-updated-#{code}", new_secret),
        "auditor"
      )

    audit = latest_audit_entry!("sink_updated", sink.id)
    detail = decoded_detail(audit)

    valid_success_audit?(audit, "auditor", "sink_updated", "forwarding_sink", updated.id) and
      is_map(detail["changes"]) and
      detail["changes"]["name"]["old"] == sink.name and
      detail["changes"]["name"]["new"] == updated.name and
      detail["secrets_changed"] == ["hec_token"] and
      detail["pool_id"] == pool.id and
      detail["pool_name"] == pool.name and
      not contains_any_secret?(audit, [old_secret, new_secret])
  end

  defp delete_audit_complete_and_safe?(code) do
    secret = "audit-delete-secret-#{code}"

    {:ok, pool} =
      Pools.create_pool(
        %{"name" => unique_name("forwarding-audit-ok-delete-#{code}")},
        "property"
      )

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        splunk_create_attrs("splunk-audit-delete-#{code}", secret),
        "auditor"
      )

    {:ok, _deleted} = Forwarding.delete_sink(pool.id, sink.id, "auditor")
    audit = audit_entry!("sink_deleted", sink.id)
    detail = decoded_detail(audit)

    valid_success_audit?(audit, "auditor", "sink_deleted", "forwarding_sink", sink.id) and
      detail["name"] == sink.name and
      detail["sink_type"] == "splunk_hec" and
      detail["pool_id"] == pool.id and
      detail["pool_name"] == pool.name and
      not contains_any_secret?(audit, [secret])
  end

  defp toggle_audit_complete_and_safe?(code) do
    {:ok, pool} =
      Pools.create_pool(
        %{"name" => unique_name("forwarding-audit-ok-toggle-#{code}")},
        "property"
      )

    {:ok, sink} = create_file_sink(pool.id, "file-audit-toggle-ok-#{code}")
    {:ok, toggled} = Forwarding.toggle_sink(pool.id, sink.id, "auditor")
    audit = audit_entry!("sink_toggled", sink.id)
    detail = decoded_detail(audit)

    valid_success_audit?(audit, "auditor", "sink_toggled", "forwarding_sink", sink.id) and
      detail["name"] == sink.name and
      detail["enabled"] == toggled.enabled and
      detail["pool_id"] == pool.id and
      detail["pool_name"] == pool.name
  end

  defp schema_audit_complete_and_safe?(code) do
    {:ok, pool} =
      Pools.create_pool(
        %{"name" => unique_name("forwarding-audit-ok-schema-#{code}")},
        "property"
      )

    {:ok, updated} = Forwarding.update_schema_mode(pool.id, "ecs", "auditor")
    audit = audit_entry!("schema_mode_changed", pool.id)
    detail = decoded_detail(audit)

    valid_success_audit?(audit, "auditor", "schema_mode_changed", "pool", pool.id) and
      detail["old_mode"] == "raw" and
      detail["new_mode"] == updated.schema_mode and
      detail["pool_name"] == pool.name
  end

  defp connection_audit_complete_and_safe?(code) do
    secret = "connection-secret-#{code}"

    {:ok, pool} =
      Pools.create_pool(%{"name" => unique_name("forwarding-audit-ok-test-#{code}")}, "property")

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        bearer_http_attrs("http-audit-test-#{code}", secret),
        "auditor"
      )

    sink_id = sink.id

    :ok =
      Forwarding.test_connection(pool.id, sink_id, self(),
        actor: "auditor",
        supervisor: Process.get(:forwarding_property_supervisor),
        tester: fn _sink ->
          %{
            success: false,
            message:
              "failed for https://user:#{secret}@collector.example/events?token=#{secret} password=#{secret}",
            error_category: "auth",
            endpoint: "https://user:#{secret}@collector.example/events?token=#{secret}"
          }
        end
      )

    assert_receive {:connection_test_result, ^sink_id, _result}, 500

    audit = audit_entry!("sink_connection_tested", sink_id)
    detail = decoded_detail(audit)

    valid_success_audit?(audit, "auditor", "sink_connection_tested", "forwarding_sink", sink_id) and
      detail["name"] == sink.name and
      detail["sink_type"] == "http" and
      detail["pool_id"] == pool.id and
      detail["pool_name"] == pool.name and
      detail["result"] == "failure" and
      detail["error_category"] == "auth" and
      detail["endpoint"] == "https://collector.example/events" and
      not contains_any_secret?(audit, [secret]) and
      not String.contains?(detail["endpoint"], "?") and
      not String.contains?(detail["endpoint"], "@")
  end

  defp create_file_sink(pool_id, name) do
    Forwarding.create_sink(pool_id, file_attrs(name), "property")
  end

  defp create_splunk_sink(pool_id, name) do
    Forwarding.create_sink(
      pool_id,
      splunk_create_attrs(name, "secret-token-#{name}"),
      "property"
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
      "property"
    )
  end

  defp apply_version_operation(:create, state) do
    with {:ok, sink} <-
           create_file_sink(state.pool_id, "file-version-#{state.code}-#{state.step}") do
      {:ok,
       %{state | sink: sink, expected_version: state.expected_version + 1, step: state.step + 1}}
    end
  end

  defp apply_version_operation(:update, state) do
    with {:ok, state} <- ensure_version_sink(state),
         {:ok, sink} <-
           Forwarding.update_sink(
             state.pool_id,
             state.sink.id,
             update_attrs_for_sink(state.sink, "version-updated-#{state.code}-#{state.step}"),
             "property"
           ) do
      {:ok,
       %{state | sink: sink, expected_version: state.expected_version + 1, step: state.step + 1}}
    end
  end

  defp apply_version_operation(:toggle, state) do
    with {:ok, state} <- ensure_version_sink(state),
         {:ok, sink} <- Forwarding.toggle_sink(state.pool_id, state.sink.id, "property") do
      {:ok,
       %{state | sink: sink, expected_version: state.expected_version + 1, step: state.step + 1}}
    end
  end

  defp apply_version_operation(:schema, state) do
    mode = Enum.at(~w(ecs ocsf splunk_cim raw), rem(state.code + state.step, 4))
    previous_mode = Repo.get!(SensorPool, state.pool_id).schema_mode

    case Forwarding.update_schema_mode(state.pool_id, mode, "property") do
      {:ok, _pool} ->
        increment = if previous_mode == mode, do: 0, else: 1

        {:ok,
         %{state | expected_version: state.expected_version + increment, step: state.step + 1}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp apply_version_operation(:test_connection, state) do
    with {:ok, state} <- ensure_http_version_sink(state),
         :ok <-
           Forwarding.test_connection(state.pool_id, state.sink.id, self(),
             actor: "property",
             supervisor: Process.get(:forwarding_property_supervisor),
             tester: fn _sink ->
               %{
                 success: true,
                 message: "ok",
                 error_category: nil,
                 endpoint: "https://8.8.8.8/collect"
               }
             end
           ),
         :ok <- receive_connection_result(state.sink.id) do
      {:ok, %{state | step: state.step + 1}}
    end
  end

  defp apply_version_operation(:delete, state) do
    with {:ok, state} <- ensure_version_sink(state),
         {:ok, _sink} <- Forwarding.delete_sink(state.pool_id, state.sink.id, "property") do
      {:ok,
       %{state | sink: nil, expected_version: state.expected_version + 1, step: state.step + 1}}
    end
  end

  defp ensure_version_sink(%{sink: %ForwardingSink{}} = state), do: {:ok, state}

  defp ensure_version_sink(state) do
    with {:ok, sink} <-
           create_file_sink(state.pool_id, "file-version-ensure-#{state.code}-#{state.step}") do
      {:ok, %{state | sink: sink, expected_version: state.expected_version + 1}}
    end
  end

  defp ensure_http_version_sink(%{sink: %ForwardingSink{sink_type: "http"}} = state),
    do: {:ok, state}

  defp ensure_http_version_sink(state) do
    with {:ok, sink} <-
           create_http_sink(state.pool_id, "http-version-#{state.code}-#{state.step}") do
      {:ok, %{state | sink: sink, expected_version: state.expected_version + 1}}
    end
  end

  defp receive_connection_result(sink_id) do
    receive do
      {:connection_test_result, ^sink_id, %{success: true}} -> :ok
    after
      500 -> {:error, :connection_test_timeout}
    end
  end

  defp persisted_forwarding_version(pool_id) do
    SensorPool
    |> Repo.get!(pool_id)
    |> Map.fetch!(:forwarding_config_version)
  end

  defp cross_pool_failure_audit_count(sink_id) do
    Repo.aggregate(
      from(a in AuditEntry,
        where:
          a.target_type == "forwarding_sink" and a.target_id == ^sink_id and
            a.result == "failure" and a.action in ^@cross_pool_failure_actions
      ),
      :count,
      :id
    )
  end

  defp secret!(sink_id, secret_name) do
    Repo.get_by!(SinkSecret, forwarding_sink_id: sink_id, secret_name: secret_name)
  end

  defp version_operations(code) do
    operations = [:create, :update, :toggle, :schema, :test_connection, :delete]

    0..5
    |> Enum.map(fn index ->
      Enum.at(operations, rem(code + index * 3, length(operations)))
    end)
  end

  defp file_attrs(name) do
    %{
      "name" => name,
      "sink_type" => "file",
      "path_template" => "/var/log/ravenwire/events.ndjson",
      "encoding" => "ndjson"
    }
  end

  defp splunk_attrs(name, token) do
    %{
      "name" => name,
      "endpoint" => "https://splunk-audit.example",
      "index" => "main",
      "hec_token" => token
    }
  end

  defp http_attrs(name) do
    %{
      "name" => name,
      "sink_type" => "http",
      "endpoint" => "https://8.8.8.8/collect",
      "method" => "POST",
      "auth_type" => "none"
    }
  end

  defp splunk_create_attrs(name, token) do
    %{
      "name" => name,
      "sink_type" => "splunk_hec",
      "endpoint" => "https://splunk.example",
      "hec_token" => token
    }
  end

  defp bearer_http_attrs(name, token) do
    %{
      "name" => name,
      "sink_type" => "http",
      "endpoint" => "https://8.8.8.8/collect",
      "method" => "POST",
      "auth_type" => "bearer",
      "bearer_token" => token
    }
  end

  defp update_attrs_for_sink(%ForwardingSink{sink_type: "http"}, suffix) do
    http_attrs("http-#{suffix}")
  end

  defp update_attrs_for_sink(_sink, suffix) do
    file_attrs("file-#{suffix}")
  end

  defp schema_mode_case(code) do
    case rem(code, 7) do
      0 -> "raw"
      1 -> "ecs"
      2 -> "ocsf"
      3 -> "splunk_cim"
      4 -> "splunk-cim"
      5 -> ""
      6 -> "unknown-#{code}"
    end
  end

  defp unique_name(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"

  defp audit_entry!(action, target_id) do
    Repo.get_by!(AuditEntry,
      action: action,
      target_id: target_id,
      result: "success"
    )
  end

  defp latest_audit_entry!(action, target_id) do
    Repo.one!(
      from(a in AuditEntry,
        where: a.action == ^action and a.target_id == ^target_id and a.result == "success",
        order_by: [desc: a.timestamp, desc: a.id],
        limit: 1
      )
    )
  end

  defp decoded_detail(%AuditEntry{} = audit), do: Jason.decode!(audit.detail)

  defp valid_success_audit?(audit, actor, action, target_type, target_id) do
    audit.actor == actor and
      audit.actor_type == "user" and
      audit.action == action and
      audit.target_type == target_type and
      audit.target_id == target_id and
      audit.result == "success" and
      audit.action in @audit_success_actions and
      is_map(decoded_detail(audit))
  end

  defp contains_any_secret?(term, secrets) do
    inspected = inspect(term)
    Enum.any?(secrets, &String.contains?(inspected, &1))
  end

  defp receive_forwarding_message(expected_event, expected_sink_id) do
    receive do
      {^expected_event, %ForwardingSink{id: ^expected_sink_id} = sink} ->
        {expected_event, sink}

      {^expected_event, payload} when is_nil(expected_sink_id) ->
        {expected_event, payload}

      {^expected_event, ^expected_sink_id} ->
        {expected_event, expected_sink_id}
    after
      500 -> flunk("expected forwarding PubSub message #{inspect(expected_event)}")
    end
  end

  defp sink_state(%ForwardingSink{} = sink) do
    Map.take(sink, [:name, :normalized_name, :sink_type, :config, :enabled])
  end

  defp secret_state(%SinkSecret{} = secret) do
    Map.take(secret, [:forwarding_sink_id, :secret_name, :ciphertext, :last_four])
  end
end
