defmodule ConfigManager.Deployments.OrchestratorPropertyTest do
  @moduledoc "Property coverage for deployment orchestrator finalization and rollback integrity."

  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.{Deployments, Pools, Repo, SensorPod}
  alias ConfigManager.Deployments.{Deployment, DeploymentResult, Orchestrator}

  defmodule OutcomeClient do
    def switch_capture_mode(%{name: "prop-success-" <> _suffix}, _config), do: {:ok, %{}}

    def switch_capture_mode(%{name: "prop-failed-" <> _suffix}, _config),
      do: {:error, {:http_error, 500, "failed"}}

    def switch_capture_mode(%{name: "prop-unreachable-" <> _suffix}, _config),
      do: {:error, :econnrefused}

    def push_rule_bundle(_pod, _rules, _opts), do: {:ok, %{}}
  end

  defmodule SuccessClient do
    def switch_capture_mode(_pod, _config), do: {:ok, %{}}
    def push_rule_bundle(_pod, _rules, _opts), do: {:ok, %{}}
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    previous_client = Application.get_env(:config_manager, :sensor_agent_client)

    on_exit(fn ->
      case previous_client do
        nil -> Application.delete_env(:config_manager, :sensor_agent_client)
        client -> Application.put_env(:config_manager, :sensor_agent_client, client)
      end
    end)

    :ok
  end

  property "Property 7: final deployment status follows per-sensor outcomes",
           [:verbose, numtests: 25] do
    forall code <- integer(0, 2_000) do
      Application.put_env(:config_manager, :sensor_agent_client, OutcomeClient)

      outcomes = outcome_list(code)
      pool = create_pool!("orchestrator-final-prop-#{code}")
      sensors = insert_outcome_sensors!(outcomes, pool.id, code)

      {:ok, deployment} =
        Deployments.create_deployment(pool, "property-operator", start_orchestrator?: false)

      {:ok, completed} = Orchestrator.run(deployment.id, max_concurrency: 2, timeout: 1_000)

      expected_successful? =
        outcomes
        |> Enum.reject(&(&1 == :skipped))
        |> Enum.all?(&(&1 == :success))

      expected_status = if expected_successful?, do: "successful", else: "failed"
      result_statuses = result_statuses(deployment.id, sensors)

      completed.status == expected_status and
        Enum.all?(outcomes, fn outcome ->
          Map.has_key?(result_statuses, expected_result_status(outcome))
        end)
    end
  end

  property "Property 8: successful deployments update only successful sensor version fields and cancelled deployments update none",
           [:verbose, numtests: 20] do
    forall code <- integer(1, 1_000) do
      Application.put_env(:config_manager, :sensor_agent_client, OutcomeClient)

      pool = create_pool!("orchestrator-version-prop-#{code}")
      outcomes = success_and_skipped_outcomes(code)
      sensors = insert_outcome_sensors!(outcomes, pool.id, code)

      {:ok, deployment} =
        Deployments.create_deployment(pool, "property-operator", start_orchestrator?: false)

      {:ok, completed} = Orchestrator.run(deployment.id, max_concurrency: 2, timeout: 1_000)

      updated_correctly? =
        sensors
        |> Enum.zip(outcomes)
        |> Enum.all?(fn {sensor, outcome} ->
          sensor = Repo.get!(SensorPod, sensor.id)

          if outcome == :success do
            sensor.last_deployment_id == deployment.id and
              sensor.last_deployed_config_version == deployment.config_version
          else
            is_nil(sensor.last_deployment_id)
          end
        end)

      cancel_pool = create_pool!("orchestrator-cancel-prop-#{code}")
      cancel_sensor = insert_sensor!("prop-success-cancel-#{code}", cancel_pool.id, true)

      {:ok, cancelled_deployment} =
        Deployments.create_deployment(cancel_pool, "property-operator",
          start_orchestrator?: false
        )

      {:ok, _cancelled} = Orchestrator.cancel(cancelled_deployment.id, "property-operator")
      cancel_sensor = Repo.get!(SensorPod, cancel_sensor.id)

      completed.status == "successful" and updated_correctly? and
        is_nil(cancel_sensor.last_deployment_id)
    end
  end

  property "Property 11: rollback deployment uses the source snapshot and marks the original rolled back on success",
           [:verbose, numtests: 15] do
    forall code <- integer(1, 1_000) do
      Application.put_env(:config_manager, :sensor_agent_client, SuccessClient)

      pool = create_pool!("rollback-integrity-prop-#{code}")
      insert_sensor!("prop-success-rollback-#{code}", pool.id, true)

      source_snapshot = snapshot_with_version(pool, rem(code, 20) + 1)
      target_snapshot = snapshot_with_version(pool, rem(code, 20) + 21)

      {:ok, source} =
        Deployments.create_deployment(pool, "property-source",
          snapshot: source_snapshot,
          start_orchestrator?: false
        )

      source = force_status!(source, "successful")

      {:ok, original} =
        Deployments.create_deployment(pool, "property-target",
          snapshot: target_snapshot,
          start_orchestrator?: false
        )

      original = force_status!(original, "failed")

      {:ok, rollback} =
        Deployments.rollback_deployment(original, "property-operator", start_orchestrator?: false)

      {:ok, completed_rollback} =
        Orchestrator.run(rollback.id, max_concurrency: 1, timeout: 1_000)

      reloaded_original = Repo.get!(Deployment, original.id)
      reloaded_source = Repo.get!(Deployment, source.id)

      rollback.config_snapshot == source_snapshot and
        rollback.rollback_of_deployment_id == original.id and
        rollback.source_deployment_id == source.id and
        completed_rollback.status == "successful" and
        reloaded_original.status == "rolled_back" and
        reloaded_source.status == "successful"
    end
  end

  defp outcome_list(code) do
    first = Enum.at([:success, :failed, :unreachable], rem(code, 3))

    rest =
      0..2
      |> Enum.map(fn index ->
        Enum.at([:success, :failed, :unreachable, :skipped], rem(div(code, pow4(index)), 4))
      end)

    [first | rest]
  end

  defp success_and_skipped_outcomes(code) do
    0..3
    |> Enum.map(fn index ->
      if Bitwise.band(code, Bitwise.bsl(1, index)) == 0, do: :success, else: :skipped
    end)
    |> ensure_success()
  end

  defp ensure_success([:skipped | rest]), do: [:success | rest]
  defp ensure_success(outcomes), do: outcomes

  defp insert_outcome_sensors!(outcomes, pool_id, code) do
    outcomes
    |> Enum.with_index()
    |> Enum.map(fn {outcome, index} ->
      insert_sensor!("prop-#{outcome}-#{code}-#{index}", pool_id, outcome != :skipped)
    end)
  end

  defp insert_sensor!(name, pool_id, deployable?) do
    control_api_host = if deployable?, do: "127.0.0.1", else: nil

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: unique_name(name),
      public_key_pem: "public-key",
      key_fingerprint: unique_name("#{name}-fingerprint"),
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "property-operator",
      control_api_host: control_api_host
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end

  defp result_statuses(deployment_id, sensors) do
    sensor_ids = MapSet.new(sensors, & &1.id)

    DeploymentResult
    |> Repo.all()
    |> Enum.filter(
      &(&1.deployment_id == deployment_id and MapSet.member?(sensor_ids, &1.sensor_pod_id))
    )
    |> Enum.frequencies_by(& &1.status)
  end

  defp expected_result_status(:success), do: "success"
  defp expected_result_status(:failed), do: "failed"
  defp expected_result_status(:unreachable), do: "unreachable"
  defp expected_result_status(:skipped), do: "skipped"

  defp create_pool!(name) do
    {:ok, pool} = Pools.create_pool(%{"name" => unique_name(name)}, "property-operator")
    pool
  end

  defp force_status!(deployment, status) do
    deployment
    |> Ecto.Changeset.change(status: status, completed_at: DateTime.utc_now())
    |> Repo.update!()
  end

  defp snapshot_with_version(pool, version) do
    pool
    |> Deployments.Snapshot.capture()
    |> put_in(["capture", "version"], version)
    |> put_in(["forwarding", "version"], version)
    |> put_in(["bpf", "version"], version)
  end

  defp pow4(0), do: 1
  defp pow4(1), do: 4
  defp pow4(2), do: 16

  defp unique_name(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"
end
