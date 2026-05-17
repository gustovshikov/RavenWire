defmodule ConfigManager.Deployments.Orchestrator do
  @moduledoc "Executes deployment lifecycle transitions and per-sensor dispatch."

  import Ecto.Query

  alias ConfigManager.{Audit, Repo, SensorAgentClient, SensorPod}
  alias ConfigManager.Deployments.{Deployment, DeploymentResult, Snapshot}

  @default_max_concurrency 5
  @default_timeout_ms 30_000

  def start(deployment_id, opts \\ []) do
    supervisor = Keyword.get(opts, :supervisor, ConfigManager.Deployments.TaskSupervisor)
    Task.Supervisor.start_child(supervisor, __MODULE__, :run, [deployment_id, opts])
  end

  def cancel(deployment_id), do: cancel(deployment_id, "system")

  def cancel(deployment_id, actor) do
    ConfigManager.Deployments.cancel_deployment(deployment_id, actor)
  end

  def run(deployment_id, opts \\ []) do
    with {:ok, deployment} <- transition(deployment_id, "validating", %{started_at: now_utc()}),
         :ok <- preflight(deployment),
         {:ok, deployment} <- transition(deployment.id, "deploying", %{}),
         :ok <- audit(deployment, "deployment_started", "success", %{}),
         :ok <- dispatch_results(deployment, opts) do
      finalize(deployment.id)
    else
      {:error, :cancelled} ->
        {:error, :cancelled}

      {:error, reason} ->
        fail_deployment(deployment_id, reason)
    end
  end

  defp preflight(deployment) do
    deployment = reload(deployment.id)

    cond do
      deployment.status == "cancelled" ->
        {:error, :cancelled}

      Snapshot.validate(deployment.config_snapshot) != :ok ->
        {:error, :invalid_snapshot}

      Enum.all?(deployment.results, &(&1.status == "skipped")) ->
        {:error, :no_deployable_sensors}

      true ->
        :ok
    end
  end

  defp dispatch_results(deployment, opts) do
    deployment = reload(deployment.id)

    if deployment.status == "cancelled" do
      {:error, :cancelled}
    else
      max_concurrency = Keyword.get(opts, :max_concurrency, @default_max_concurrency)
      timeout = Keyword.get(opts, :timeout, @default_timeout_ms)
      pending_results = Enum.filter(deployment.results, &(&1.status == "pending"))

      pending_results
      |> Task.async_stream(&dispatch_result(&1.id, deployment.id),
        max_concurrency: max_concurrency,
        timeout: timeout,
        on_timeout: :kill_task
      )
      |> Enum.zip(pending_results)
      |> Enum.each(fn
        {{:ok, _result}, _pending_result} -> :ok
        {{:exit, reason}, pending_result} -> mark_result_timeout(pending_result, reason)
      end)

      :ok
    end
  end

  defp dispatch_result(result_id, deployment_id) do
    result =
      DeploymentResult
      |> preload(:sensor_pod)
      |> Repo.get!(result_id)

    deployment = reload(deployment_id)

    if deployment.status == "cancelled" do
      update_result(result, %{
        status: "skipped",
        completed_at: now_utc(),
        message: "deployment cancelled"
      })
    else
      started_at = now_utc()
      {:ok, result} = update_result(result, %{status: "pushing", started_at: started_at})

      case push_snapshot(result.sensor_pod, deployment.config_snapshot) do
        :ok ->
          {:ok, updated} =
            update_result(result, %{
              status: "success",
              completed_at: now_utc(),
              message: "deployment applied"
            })

          updated

        {:error, reason} ->
          status = error_status(reason)

          {:ok, updated} =
            update_result(result, %{
              status: status,
              completed_at: now_utc(),
              message: format_reason(reason)
            })

          updated
      end
    end
  end

  defp push_snapshot(sensor, snapshot) do
    with :ok <- push_capture(sensor, snapshot["capture"]),
         :ok <- push_rules(sensor, snapshot["rules"]) do
      :ok
    end
  end

  defp push_capture(sensor, capture) do
    config = %{
      pcap_ring_size_mb: capture["pcap_ring_size_mb"],
      pre_alert_window_sec: capture["pre_alert_window_sec"],
      post_alert_window_sec: capture["post_alert_window_sec"],
      alert_severity_threshold: capture["alert_severity_threshold"]
    }

    case client().switch_capture_mode(sensor, config) do
      {:ok, _body} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp push_rules(_sensor, %{"files" => files}) when files in [%{}, nil], do: :ok

  defp push_rules(sensor, %{"files" => files, "version" => version}) do
    case client().push_rule_bundle(sensor, files || %{}, version: version || 0) do
      {:ok, _body} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp push_rules(_sensor, _rules), do: :ok

  defp finalize(deployment_id) do
    deployment = reload(deployment_id)

    if deployment.status == "cancelled" do
      {:error, :cancelled}
    else
      non_skipped = Enum.reject(deployment.results, &(&1.status == "skipped"))
      successful? = non_skipped != [] and Enum.all?(non_skipped, &(&1.status == "success"))
      final_status = if successful?, do: "successful", else: "failed"
      failure_reason = if successful?, do: nil, else: "one or more sensor results failed"

      with {:ok, finalized} <-
             transition(deployment.id, final_status, %{
               completed_at: now_utc(),
               failure_reason: failure_reason
             }),
           :ok <-
             audit(
               finalized,
               "deployment_completed",
               audit_result(final_status),
               result_summary(finalized)
             ),
           :ok <- maybe_mark_successful_sensors(finalized),
           :ok <- maybe_mark_rollback_complete(finalized) do
        broadcast(finalized, {:deployment_completed, finalized.id})
        {:ok, finalized}
      end
    end
  end

  defp fail_deployment(deployment_id, reason) do
    deployment = Repo.get(Deployment, deployment_id)

    cond do
      is_nil(deployment) ->
        {:error, reason}

      deployment.status == "cancelled" ->
        {:error, :cancelled}

      deployment.status == "pending" ->
        case transition(deployment.id, "validating", %{started_at: now_utc()}) do
          {:ok, _validating} -> fail_deployment(deployment_id, reason)
          {:error, transition_reason} -> {:error, transition_reason}
        end

      deployment.status in ["validating", "deploying"] ->
        case transition(deployment.id, "failed", %{
               completed_at: now_utc(),
               failure_reason: format_reason(reason)
             }) do
          {:ok, failed} ->
            audit(failed, "deployment_completed", "failure", %{reason: format_reason(reason)})
            broadcast(failed, {:deployment_completed, failed.id})
            {:error, reason}

          {:error, transition_reason} ->
            {:error, transition_reason}
        end

      true ->
        {:error, reason}
    end
  end

  defp mark_result_timeout(pending_result, reason) do
    result =
      DeploymentResult
      |> preload(:sensor_pod)
      |> Repo.get!(pending_result.id)

    deployment = Repo.get!(Deployment, result.deployment_id)

    attrs =
      if deployment.status == "cancelled" do
        %{
          status: "skipped",
          completed_at: now_utc(),
          message: "deployment cancelled"
        }
      else
        %{
          status: "failed",
          completed_at: now_utc(),
          message: timeout_message(reason)
        }
      end

    update_result(result, attrs)
    :ok
  end

  defp maybe_mark_successful_sensors(%Deployment{status: "successful"} = deployment) do
    deployment
    |> reload()
    |> Map.fetch!(:results)
    |> Enum.filter(&(&1.status == "success"))
    |> Enum.each(fn result ->
      result.sensor_pod
      |> SensorPod.deployment_success_changeset(deployment)
      |> Repo.update!()
    end)

    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "pool:#{deployment.pool_id}:drift",
      {:drift_updated, deployment.pool_id}
    )

    :ok
  end

  defp maybe_mark_successful_sensors(_deployment), do: :ok

  defp maybe_mark_rollback_complete(
         %Deployment{status: "successful", rollback_of_deployment_id: rollback_id} = deployment
       )
       when not is_nil(rollback_id) do
    original = Repo.get!(Deployment, rollback_id)

    {:ok, rolled_back} =
      original
      |> Deployment.status_changeset("rolled_back")
      |> Repo.update()

    audit(rolled_back, "deployment_rolled_back", "success", %{
      rollback_deployment_id: deployment.id
    })

    broadcast(rolled_back, {:deployment_rolled_back, rolled_back.id})
    :ok
  end

  defp maybe_mark_rollback_complete(_deployment), do: :ok

  defp transition(deployment_id, status, attrs) do
    deployment = Repo.get!(Deployment, deployment_id)

    case Deployment.status_changeset(deployment, status, attrs) |> Repo.update() do
      {:ok, updated} ->
        updated = reload(updated.id)
        broadcast(updated, {:deployment_status_changed, updated.id})
        {:ok, updated}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  defp update_result(result, attrs) do
    case result |> DeploymentResult.update_changeset(attrs) |> Repo.update() do
      {:ok, updated} ->
        updated = Repo.preload(updated, :sensor_pod)
        broadcast(reload(updated.deployment_id), {:result_updated, updated.id})
        {:ok, updated}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  defp result_summary(deployment) do
    deployment
    |> reload()
    |> Map.fetch!(:results)
    |> Enum.frequencies_by(& &1.status)
  end

  defp audit(deployment, action, result, detail) do
    Audit.log(%{
      actor: "system",
      actor_type: "system",
      action: action,
      target_type: "deployment",
      target_id: deployment.id,
      result: result,
      detail: Map.put(detail, :pool_id, deployment.pool_id)
    })

    :ok
  end

  defp reload(%Deployment{id: id}), do: reload(id)

  defp reload(id) do
    Deployment
    |> preload(results: :sensor_pod)
    |> Repo.get!(id)
  end

  defp client do
    Application.get_env(:config_manager, :sensor_agent_client, SensorAgentClient)
  end

  defp error_status(:no_control_api_host), do: "unreachable"
  defp error_status({:http_error, _status, _body}), do: "failed"
  defp error_status({:validation_error, _body}), do: "failed"
  defp error_status(_reason), do: "unreachable"

  defp audit_result("successful"), do: "success"
  defp audit_result(_status), do: "failure"

  defp format_reason(reason) when is_binary(reason), do: reason
  defp format_reason(reason), do: inspect(reason)

  defp timeout_message(:timeout), do: "deployment task timed out"
  defp timeout_message(reason), do: format_reason(reason)

  defp broadcast(deployment, message) do
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "deployments", message)
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "deployment:#{deployment.id}", message)

    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "pool:#{deployment.pool_id}:deployments",
      message
    )
  end

  defp now_utc, do: DateTime.utc_now()
end
