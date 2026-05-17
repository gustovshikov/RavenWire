defmodule ConfigManager.DeploymentsTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.{AuditEntry, Deployments, Pools, Repo, SensorPod}
  alias ConfigManager.Deployments.{Deployment, DeploymentResult}

  test "creates deployment with per-sensor results and prevents concurrent active deployment" do
    {:ok, pool} = Pools.create_pool(%{"name" => "deploy-pool"}, "tester")
    deployable = insert_sensor!("deployable-sensor", pool.id, control_api_host: "127.0.0.1")
    skipped = insert_sensor!("skipped-sensor", pool.id)

    assert {:ok, deployment} =
             Deployments.create_deployment(pool, "tester", start_orchestrator?: false)

    assert deployment.status == "pending"
    assert deployment.config_version == pool.config_version
    assert deployment.config_snapshot["capture"]["version"] == pool.config_version
    assert length(deployment.results) == 2

    assert result_status(deployment, deployable.id) == "pending"
    assert result_status(deployment, skipped.id) == "skipped"

    assert Deployments.has_active_deployment?(pool.id)

    assert {:error, :active_deployment_exists} =
             Deployments.create_deployment(pool, "tester", start_orchestrator?: false)

    audit = Repo.get_by!(AuditEntry, action: "deployment_created", target_id: deployment.id)
    assert audit.detail =~ pool.id
  end

  test "rejects deployment when no enrolled sensor has a Control API host" do
    {:ok, pool} = Pools.create_pool(%{"name" => "no-deployable-pool"}, "tester")
    insert_sensor!("no-control-api", pool.id)

    assert {:error, :no_deployable_sensors} = Deployments.create_deployment(pool, "tester")
  end

  test "cancels active deployment and marks remaining results skipped" do
    {:ok, pool} = Pools.create_pool(%{"name" => "cancel-pool"}, "tester")
    insert_sensor!("cancel-sensor", pool.id, control_api_host: "127.0.0.1")
    {:ok, deployment} = Deployments.create_deployment(pool, "tester", start_orchestrator?: false)

    assert {:ok, cancelled} = Deployments.cancel_deployment(deployment, "tester")
    assert cancelled.status == "cancelled"
    refute Deployments.has_active_deployment?(pool.id)

    results =
      DeploymentResult
      |> Repo.all()
      |> Enum.filter(&(&1.deployment_id == deployment.id))

    assert Enum.all?(results, &(&1.status == "skipped"))
    assert Repo.get_by!(AuditEntry, action: "deployment_cancelled", target_id: deployment.id)
  end

  test "drift detector classifies never deployed, in-sync, and drifted sensors" do
    {:ok, pool} = Pools.create_pool(%{"name" => "drift-pool"}, "tester")
    never = insert_sensor!("never-deployed", pool.id, control_api_host: "127.0.0.1")

    in_sync =
      insert_sensor!("in-sync", pool.id, control_api_host: "127.0.0.1")
      |> SensorPod.deployment_success_changeset(%{
        last_deployed_config_version: pool.config_version,
        last_deployed_forwarding_version: 0,
        last_deployed_at: DateTime.utc_now()
      })
      |> Repo.update!()

    drifted =
      insert_sensor!("drifted", pool.id, control_api_host: "127.0.0.1")
      |> SensorPod.deployment_success_changeset(%{
        last_deployed_config_version: pool.config_version + 1,
        last_deployed_forwarding_version: 0,
        last_deployed_at: DateTime.utc_now()
      })
      |> Repo.update!()

    by_sensor =
      pool
      |> Deployments.compute_drift()
      |> Map.new(fn result -> {result.sensor.id, result} end)

    assert by_sensor[never.id].status == :never_deployed
    assert by_sensor[in_sync.id].status == :in_sync
    assert by_sensor[drifted.id].status == :drift_detected
    assert by_sensor[drifted.id].domains == [:capture]

    assert %{total: 3, never_deployed: 1, in_sync: 1, drift_detected: 1} =
             Deployments.drift_summary(pool)

    assert Deployments.pool_has_drift?(pool)
  end

  test "list_deployments filters by pool and status" do
    {:ok, pool_a} = Pools.create_pool(%{"name" => "list-pool-a"}, "tester")
    {:ok, pool_b} = Pools.create_pool(%{"name" => "list-pool-b"}, "tester")
    insert_sensor!("list-a", pool_a.id, control_api_host: "127.0.0.1")
    insert_sensor!("list-b", pool_b.id, control_api_host: "127.0.0.1")

    {:ok, deployment_a} =
      Deployments.create_deployment(pool_a, "tester", start_orchestrator?: false)

    {:ok, _deployment_b} =
      Deployments.create_deployment(pool_b, "tester", start_orchestrator?: false)

    {:ok, _cancelled} = Deployments.cancel_deployment(deployment_a, "tester")

    assert %{entries: [only_cancelled], total_count: 1} =
             Deployments.list_deployments(pool_id: pool_a.id, status: "cancelled")

    assert only_cancelled.pool_id == pool_a.id
  end

  test "rollback creates a deployment from the previous successful snapshot and audits initiation" do
    {:ok, pool} = Pools.create_pool(%{"name" => "rollback-pool"}, "tester")
    insert_sensor!("rollback-sensor", pool.id, control_api_host: "127.0.0.1")

    {:ok, source} = Deployments.create_deployment(pool, "tester", start_orchestrator?: false)
    source = complete_deployment!(source, "successful")

    {:ok, target} = Deployments.create_deployment(pool, "tester", start_orchestrator?: false)
    target = complete_deployment!(target, "failed")

    assert {:ok, rollback} =
             Deployments.rollback_deployment(target, "tester", start_orchestrator?: false)

    assert rollback.rollback_of_deployment_id == target.id
    assert rollback.source_deployment_id == source.id
    assert rollback.config_snapshot == source.config_snapshot

    audit =
      Repo.get_by!(AuditEntry,
        action: "deployment_rollback_initiated",
        target_id: rollback.id,
        result: "success"
      )

    assert audit.detail =~ target.id
    assert audit.detail =~ source.id
  end

  defp result_status(%Deployment{} = deployment, sensor_id) do
    deployment.results
    |> Enum.find(&(&1.sensor_pod_id == sensor_id))
    |> Map.fetch!(:status)
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

  defp insert_sensor!(name, pool_id, opts \\ []) do
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
