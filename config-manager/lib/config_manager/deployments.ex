defmodule ConfigManager.Deployments do
  @moduledoc "Deployment tracking, drift detection, and deployment result helpers."

  import Ecto.Query

  alias ConfigManager.{Audit, Repo, SensorPod, SensorPool}

  alias ConfigManager.Deployments.{
    Deployment,
    DeploymentResult,
    Diff,
    DriftDetector,
    Orchestrator,
    Snapshot
  }

  alias Ecto.Multi

  def list_deployments(opts \\ []) do
    page = max(to_int(Keyword.get(opts, :page, 1)), 1)
    page_size = max(to_int(Keyword.get(opts, :page_size, 25)), 1)

    query =
      Deployment
      |> maybe_filter(:pool_id, Keyword.get(opts, :pool_id))
      |> maybe_filter(:status, Keyword.get(opts, :status))
      |> maybe_filter(:operator, Keyword.get(opts, :operator))
      |> maybe_inserted_after(Keyword.get(opts, :inserted_after))
      |> maybe_inserted_before(Keyword.get(opts, :inserted_before))
      |> order_by([d], desc: d.inserted_at)

    %{
      entries:
        query
        |> preload([:pool, :results])
        |> limit(^page_size)
        |> offset(^((page - 1) * page_size))
        |> Repo.all(),
      page: page,
      page_size: page_size,
      total_count: Repo.aggregate(query, :count, :id)
    }
  end

  def list_pool_deployments(pool_id, opts \\ []) do
    list_deployments(Keyword.put(opts, :pool_id, pool_id))
  end

  def get_deployment(id) do
    Deployment
    |> preload([:pool, results: :sensor_pod])
    |> Repo.get(id)
  end

  def get_deployment!(id) do
    Deployment
    |> preload([:pool, results: :sensor_pod])
    |> Repo.get!(id)
  end

  def create_deployment(pool_or_id, actor, opts \\ []) do
    pool = get_pool!(pool_or_id)
    enrolled_sensors = enrolled_sensors(pool.id)
    deployable_sensors = Enum.reject(enrolled_sensors, &no_control_api?/1)

    cond do
      has_active_deployment?(pool.id) ->
        {:error, :active_deployment_exists}

      deployable_sensors == [] ->
        {:error, :no_deployable_sensors}

      true ->
        insert_deployment(pool, enrolled_sensors, actor, opts)
    end
  end

  def cancel_deployment(%Deployment{} = deployment, actor) do
    deployment = Repo.reload!(deployment)

    if deployment.status in Deployment.active_statuses() do
      now = DateTime.utc_now()

      Multi.new()
      |> Multi.update(
        :deployment,
        Deployment.status_changeset(deployment, "cancelled", %{completed_at: now})
      )
      |> Multi.update_all(
        :remaining_results,
        from(r in DeploymentResult,
          where: r.deployment_id == ^deployment.id and r.status in ["pending", "pushing"]
        ),
        set: [status: "skipped", completed_at: now, message: "deployment cancelled"]
      )
      |> Audit.append_multi(fn %{deployment: cancelled} ->
        audit_attrs(actor, "deployment_cancelled", "deployment", cancelled.id, "success", %{
          pool_id: cancelled.pool_id
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{deployment: cancelled}} ->
          broadcast_deployment(cancelled, {:deployment_cancelled, cancelled.id})
          {:ok, cancelled}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    else
      {:error, :deployment_not_cancellable}
    end
  end

  def cancel_deployment(deployment_id, actor) when is_binary(deployment_id) do
    deployment_id
    |> get_deployment!()
    |> cancel_deployment(actor)
  end

  def rollback_deployment(deployment_or_id, actor, opts \\ [])

  def rollback_deployment(%Deployment{} = deployment, actor, opts) do
    deployment = Repo.reload!(deployment)

    cond do
      deployment.status == "rolled_back" ->
        {:error, :already_rolled_back}

      has_active_deployment?(deployment.pool_id) ->
        {:error, :active_deployment_exists}

      true ->
        case previous_successful_deployment(deployment) do
          nil ->
            {:error, :no_previous_successful_deployment}

          source ->
            opts =
              opts
              |> Keyword.put(:snapshot, source.config_snapshot)
              |> Keyword.put(:rollback_of_deployment_id, deployment.id)
              |> Keyword.put(:source_deployment_id, source.id)

            with {:ok, rollback} <- create_deployment(deployment.pool_id, actor, opts) do
              log_rollback_initiated(rollback, source, deployment, actor)
              {:ok, rollback}
            end
        end
    end
  end

  def rollback_deployment(deployment_id, actor, opts) when is_binary(deployment_id) do
    deployment_id
    |> get_deployment!()
    |> rollback_deployment(actor, opts)
  end

  def has_active_deployment?(pool_id) do
    Repo.exists?(
      from(d in Deployment,
        where: d.pool_id == ^pool_id and d.status in ^Deployment.active_statuses()
      )
    )
  end

  def last_successful_deployment(pool_id) do
    Repo.one(
      from(d in Deployment,
        where: d.pool_id == ^pool_id and d.status == "successful",
        order_by: [desc: d.inserted_at],
        limit: 1
      )
    )
  end

  def last_deployment(pool_id) do
    Repo.one(
      from(d in Deployment,
        where: d.pool_id == ^pool_id,
        order_by: [desc: d.inserted_at],
        limit: 1
      )
    )
  end

  def previous_successful_deployment(%Deployment{} = deployment) do
    Repo.one(
      from(d in Deployment,
        where:
          d.pool_id == ^deployment.pool_id and d.status == "successful" and
            d.id != ^deployment.id and d.inserted_at <= ^deployment.inserted_at,
        order_by: [desc: d.inserted_at, desc: d.id],
        limit: 1
      )
    )
  end

  def compute_drift(pool_or_id), do: DriftDetector.compute(pool_or_id)

  def drift_summary(pool_or_id) do
    pool_or_id
    |> compute_drift()
    |> DriftDetector.summary()
  end

  def pool_has_drift?(pool_or_id) do
    Enum.any?(compute_drift(pool_or_id), &(&1.status in [:drift_detected, :never_deployed]))
  end

  def sensor_drift(%SensorPod{} = sensor), do: DriftDetector.sensor_drift(sensor)

  def list_deployment_results(%Deployment{} = deployment),
    do: list_deployment_results(deployment.id)

  def list_deployment_results(deployment_id) when is_binary(deployment_id) do
    DeploymentResult
    |> where([r], r.deployment_id == ^deployment_id)
    |> preload(:sensor_pod)
    |> Repo.all()
    |> Enum.sort_by(&result_sort_key/1)
    |> Enum.group_by(& &1.status)
  end

  def result_summary(%Deployment{results: results}) when is_list(results) do
    summarize_results(results)
  end

  def result_summary(%Deployment{} = deployment) do
    deployment.id
    |> list_deployment_results()
    |> Map.values()
    |> List.flatten()
    |> summarize_results()
  end

  def result_summary(deployment_id) when is_binary(deployment_id) do
    deployment_id
    |> list_deployment_results()
    |> Map.values()
    |> List.flatten()
    |> summarize_results()
  end

  defp insert_deployment(pool, enrolled_sensors, actor, opts) do
    snapshot = Keyword.get(opts, :snapshot) || Snapshot.capture(pool)

    case Snapshot.validate(snapshot) do
      :ok ->
        previous = last_successful_deployment(pool.id)
        diff = Diff.compute(previous && previous.config_snapshot, snapshot)

        deployment_attrs = %{
          pool_id: pool.id,
          status: "pending",
          operator: actor_name(actor),
          operator_type: actor_type(actor),
          config_version: snapshot["capture"]["version"],
          forwarding_config_version: snapshot["forwarding"]["version"],
          bpf_version: snapshot["bpf"]["version"],
          config_snapshot: snapshot,
          diff_summary: diff,
          rollback_of_deployment_id: Keyword.get(opts, :rollback_of_deployment_id),
          source_deployment_id: Keyword.get(opts, :source_deployment_id)
        }

        Multi.new()
        |> Multi.insert(:deployment, Deployment.create_changeset(%Deployment{}, deployment_attrs))
        |> insert_result_changes(enrolled_sensors)
        |> Audit.append_multi(fn %{deployment: deployment} ->
          audit_attrs(actor, "deployment_created", "deployment", deployment.id, "success", %{
            pool_id: pool.id,
            pool_name: pool.name,
            config_version: deployment.config_version,
            sensor_count: length(enrolled_sensors),
            rollback_of_deployment_id: deployment.rollback_of_deployment_id,
            source_deployment_id: deployment.source_deployment_id
          })
        end)
        |> Repo.transaction()
        |> case do
          {:ok, %{deployment: deployment}} ->
            deployment = get_deployment!(deployment.id)
            broadcast_deployment(deployment, {:deployment_created, deployment.id})
            maybe_start_orchestrator(deployment, opts)
            {:ok, deployment}

          {:error, _step, reason, _changes} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp insert_result_changes(multi, sensors) do
    Enum.reduce(sensors, multi, fn sensor, multi ->
      Multi.insert(multi, {:result, sensor.id}, fn %{deployment: deployment} ->
        DeploymentResult.create_changeset(%DeploymentResult{}, result_attrs(deployment, sensor))
      end)
    end)
  end

  defp result_attrs(deployment, sensor) do
    if no_control_api?(sensor) do
      %{
        deployment_id: deployment.id,
        sensor_pod_id: sensor.id,
        status: "skipped",
        message: "no Control API host"
      }
    else
      %{deployment_id: deployment.id, sensor_pod_id: sensor.id, status: "pending"}
    end
  end

  defp enrolled_sensors(pool_id) do
    Repo.all(
      from(p in SensorPod,
        where: p.pool_id == ^pool_id and p.status == "enrolled",
        order_by: [asc: p.name]
      )
    )
  end

  defp get_pool!(%SensorPool{} = pool), do: pool
  defp get_pool!(pool_id) when is_binary(pool_id), do: Repo.get!(SensorPool, pool_id)

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, _field, ""), do: query
  defp maybe_filter(query, field, value), do: where(query, [d], field(d, ^field) == ^value)

  defp maybe_inserted_after(query, nil), do: query
  defp maybe_inserted_after(query, datetime), do: where(query, [d], d.inserted_at >= ^datetime)

  defp maybe_inserted_before(query, nil), do: query
  defp maybe_inserted_before(query, datetime), do: where(query, [d], d.inserted_at <= ^datetime)

  defp result_sort_key(result) do
    order = %{
      "failed" => 0,
      "unreachable" => 1,
      "pushing" => 2,
      "pending" => 3,
      "skipped" => 4,
      "success" => 5
    }

    {Map.get(order, result.status, 9), result.sensor_pod && result.sensor_pod.name}
  end

  defp summarize_results(results) do
    counts = Enum.frequencies_by(results, & &1.status)

    %{
      total: length(results),
      pending: Map.get(counts, "pending", 0),
      pushing: Map.get(counts, "pushing", 0),
      success: Map.get(counts, "success", 0),
      failed: Map.get(counts, "failed", 0),
      unreachable: Map.get(counts, "unreachable", 0),
      skipped: Map.get(counts, "skipped", 0)
    }
  end

  defp maybe_start_orchestrator(deployment, opts) do
    if Keyword.get(opts, :start_orchestrator?, true) do
      Orchestrator.start(deployment.id)
    end
  end

  defp log_rollback_initiated(rollback, source, original, actor) do
    Audit.log(
      audit_attrs(actor, "deployment_rollback_initiated", "deployment", rollback.id, "success", %{
        pool_id: rollback.pool_id,
        rollback_of_deployment_id: original.id,
        source_deployment_id: source.id
      })
    )

    :ok
  end

  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor), do: actor
  defp actor_name(_actor), do: "system"

  defp actor_type(%{__struct__: ConfigManager.Auth.ApiToken}), do: "api_token"
  defp actor_type(%{username: _username}), do: "user"
  defp actor_type("system"), do: "system"
  defp actor_type(_actor), do: "user"

  defp audit_attrs(actor, action, target_type, target_id, result, detail) do
    %{
      actor: actor_name(actor),
      actor_type: actor_type(actor),
      action: action,
      target_type: target_type,
      target_id: target_id,
      result: result,
      detail: detail
    }
  end

  defp no_control_api?(%{control_api_host: host}), do: is_nil(host) or host == ""

  defp broadcast_deployment(deployment, message) do
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "deployments", message)
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "deployment:#{deployment.id}", message)

    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "pool:#{deployment.pool_id}:deployments",
      message
    )
  end

  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) do
    case Integer.parse(to_string(value)) do
      {int, _rest} -> int
      :error -> 1
    end
  end
end
