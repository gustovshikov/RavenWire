defmodule ConfigManager.Deployments.OrchestratorTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.{AuditEntry, Deployments, Pools, Repo, SensorPod}
  alias ConfigManager.Deployments.{Deployment, DeploymentResult, Orchestrator}

  defmodule SuccessClient do
    def switch_capture_mode(_pod, _config), do: {:ok, %{"status" => "applied"}}
    def push_rule_bundle(_pod, _rules, _opts), do: {:ok, %{"status" => "applied"}}
  end

  defmodule FailingClient do
    def switch_capture_mode(_pod, _config), do: {:error, {:http_error, 422, "bad config"}}
    def push_rule_bundle(_pod, _rules, _opts), do: {:ok, %{"status" => "applied"}}
  end

  test "run completes a successful deployment and records deployed versions" do
    put_sensor_agent_client(SuccessClient)

    {:ok, pool} = Pools.create_pool(%{"name" => "orchestrator-success-pool"}, "tester")
    sensor = insert_sensor!("orchestrator-success-sensor", pool.id, control_api_host: "127.0.0.1")

    {:ok, deployment} =
      Deployments.create_deployment(pool, "tester",
        snapshot: snapshot_with_rules(pool),
        start_orchestrator?: false
      )

    assert {:ok, completed} =
             Orchestrator.run(deployment.id, max_concurrency: 1, timeout: 1_000)

    assert completed.status == "successful"

    result =
      Repo.get_by!(DeploymentResult, deployment_id: deployment.id, sensor_pod_id: sensor.id)

    assert result.status == "success"
    assert result.message == "deployment applied"

    sensor = Repo.get!(SensorPod, sensor.id)
    assert sensor.last_deployment_id == deployment.id
    assert sensor.last_deployed_config_version == deployment.config_version
    assert sensor.last_deployed_forwarding_version == deployment.forwarding_config_version

    assert Repo.get_by!(AuditEntry, action: "deployment_started", target_id: deployment.id)

    audit =
      Repo.get_by!(AuditEntry,
        action: "deployment_completed",
        target_id: deployment.id,
        result: "success"
      )

    assert audit.detail =~ "success"
  end

  test "run marks deployment failed when a sensor push fails" do
    put_sensor_agent_client(FailingClient)

    {:ok, pool} = Pools.create_pool(%{"name" => "orchestrator-failure-pool"}, "tester")
    sensor = insert_sensor!("orchestrator-failure-sensor", pool.id, control_api_host: "127.0.0.1")

    {:ok, deployment} =
      Deployments.create_deployment(pool, "tester",
        snapshot: snapshot_with_rules(pool),
        start_orchestrator?: false
      )

    assert {:ok, completed} =
             Orchestrator.run(deployment.id, max_concurrency: 1, timeout: 1_000)

    assert completed.status == "failed"
    assert completed.failure_reason == "one or more sensor results failed"

    result =
      Repo.get_by!(DeploymentResult, deployment_id: deployment.id, sensor_pod_id: sensor.id)

    assert result.status == "failed"
    assert result.message =~ "bad config"

    sensor = Repo.get!(SensorPod, sensor.id)
    refute sensor.last_deployment_id

    assert Repo.get_by!(AuditEntry,
             action: "deployment_completed",
             target_id: deployment.id,
             result: "failure"
           )
  end

  test "successful rollback deployment marks the original deployment rolled back" do
    put_sensor_agent_client(SuccessClient)

    {:ok, pool} = Pools.create_pool(%{"name" => "orchestrator-rollback-pool"}, "tester")
    insert_sensor!("orchestrator-rollback-sensor", pool.id, control_api_host: "127.0.0.1")

    {:ok, source} = Deployments.create_deployment(pool, "tester", start_orchestrator?: false)
    source = complete_deployment!(source, "successful")

    {:ok, original} = Deployments.create_deployment(pool, "tester", start_orchestrator?: false)
    original = complete_deployment!(original, "failed")

    assert {:ok, rollback} =
             Deployments.rollback_deployment(original, "tester", start_orchestrator?: false)

    assert {:ok, completed} =
             Orchestrator.run(rollback.id, max_concurrency: 1, timeout: 1_000)

    assert completed.status == "successful"
    assert Repo.get!(Deployment, original.id).status == "rolled_back"
    assert Repo.get!(Deployment, source.id).status == "successful"

    assert Repo.get_by!(AuditEntry,
             action: "deployment_rolled_back",
             target_id: original.id,
             result: "success"
           )
  end

  defp put_sensor_agent_client(client) do
    previous_client = Application.get_env(:config_manager, :sensor_agent_client)
    Application.put_env(:config_manager, :sensor_agent_client, client)

    on_exit(fn ->
      case previous_client do
        nil -> Application.delete_env(:config_manager, :sensor_agent_client)
        client -> Application.put_env(:config_manager, :sensor_agent_client, client)
      end
    end)
  end

  defp snapshot_with_rules(pool) do
    pool
    |> Deployments.Snapshot.capture()
    |> put_in(["rules", "version"], 1)
    |> put_in(["rules", "files"], %{
      "local.rules" => "alert tcp any any -> any any (msg:\"test\"; sid:1; rev:1;)"
    })
  end

  defp complete_deployment!(deployment, status) when status in ["successful", "failed"] do
    deployment
    |> transition!("validating", %{started_at: DateTime.utc_now()})
    |> transition!("deploying")
    |> transition!(status, %{completed_at: DateTime.utc_now()})
  end

  defp transition!(deployment, status, attrs \\ %{}) do
    deployment
    |> Deployment.status_changeset(status, attrs)
    |> Repo.update!()
  end

  defp insert_sensor!(name, pool_id, opts) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "tester",
      control_api_host: Keyword.get(opts, :control_api_host)
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end
end
