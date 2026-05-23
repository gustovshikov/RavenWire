defmodule ConfigManager.Pools do
  @moduledoc "Pool management context for sensor pool CRUD, membership, and config profiles."

  import Ecto.Query

  alias ConfigManager.{Audit, AuditEntry, Repo, SensorPod, SensorPool}
  alias ConfigManager.Forwarding.{ForwardingSink, SinkSecret}
  alias Ecto.Multi

  @deployment_actions ~w(rule_deployed pool_config_deployed deployment_created deployment_completed deployment_failed)

  def list_pools(_opts \\ []) do
    pools = Repo.all(from(p in SensorPool, order_by: [asc: p.name]))
    counts = member_counts()
    status_counts = status_counts()

    Enum.map(pools, fn pool ->
      %{
        pool: pool,
        member_count: Map.get(counts, pool.id, 0),
        status_counts: Map.get(status_counts, pool.id, %{})
      }
    end)
  end

  def get_pool(id), do: Repo.get(SensorPool, id)
  def get_pool!(id), do: Repo.get!(SensorPool, id)

  def change_pool(%SensorPool{} = pool, attrs \\ %{}, actor \\ "system") do
    SensorPool.create_changeset(pool, attrs, actor)
  end

  def change_pool_metadata(%SensorPool{} = pool, attrs \\ %{}) do
    SensorPool.metadata_changeset(pool, attrs)
  end

  def change_pool_config(%SensorPool{} = pool, attrs \\ %{}, actor \\ "system") do
    SensorPool.config_update_changeset(pool, attrs, actor)
  end

  def create_pool(attrs, actor) do
    changeset = SensorPool.create_changeset(%SensorPool{}, attrs, actor_name(actor))

    Multi.new()
    |> Multi.insert(:pool, changeset)
    |> Audit.append_multi(fn %{pool: pool} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "pool_created",
        target_type: "pool",
        target_id: pool.id,
        result: "success",
        detail: %{name: pool.name, capture_mode: pool.capture_mode}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{pool: pool}} ->
        broadcast_pools({:pool_created, pool.id})
        {:ok, pool}

      {:error, :pool, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def update_pool(%SensorPool{} = pool, attrs, actor) do
    changeset = SensorPool.metadata_changeset(pool, attrs)
    old = Map.take(pool, [:name, :description])

    Multi.new()
    |> Multi.update(:pool, changeset)
    |> Audit.append_multi(fn %{pool: updated} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "pool_updated",
        target_type: "pool",
        target_id: updated.id,
        result: "success",
        detail: %{old: old, new: Map.take(updated, [:name, :description])}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{pool: updated}} ->
        broadcast_pool(updated.id, {:pool_updated, updated.id})
        broadcast_pools({:pool_updated, updated.id})
        {:ok, updated}

      {:error, :pool, changeset, _changes} ->
        log_pool_failure(pool, actor, "pool_updated", %{reason: "validation_failed"})
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def delete_pool(%SensorPool{} = pool, actor) do
    affected_sensor_count = member_count(pool.id)
    pool_sink_ids = from(s in ForwardingSink, where: s.pool_id == ^pool.id, select: s.id)

    Multi.new()
    |> Multi.update_all(:nilify_sensors, from(p in SensorPod, where: p.pool_id == ^pool.id),
      set: [pool_id: nil]
    )
    |> Multi.delete_all(
      :delete_forwarding_secrets,
      from(s in SinkSecret, where: s.forwarding_sink_id in subquery(pool_sink_ids))
    )
    |> Multi.delete_all(
      :delete_forwarding_sinks,
      from(s in ForwardingSink, where: s.pool_id == ^pool.id)
    )
    |> Multi.delete(:pool, pool)
    |> Audit.append_multi(fn _changes ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "pool_deleted",
        target_type: "pool",
        target_id: pool.id,
        result: "success",
        detail: %{name: pool.name, affected_sensor_count: affected_sensor_count}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{pool: deleted}} ->
        broadcast_pool(pool.id, {:pool_deleted, pool.id})
        broadcast_pools({:pool_deleted, pool.id})
        {:ok, deleted}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def list_pool_sensors(pool_id) do
    Repo.all(from(p in SensorPod, where: p.pool_id == ^pool_id, order_by: [asc: p.name]))
  end

  def list_unassigned_sensors do
    Repo.all(
      from(p in SensorPod,
        where: is_nil(p.pool_id) and p.status == "enrolled",
        order_by: [asc: p.name]
      )
    )
  end

  def list_other_pool_sensors(pool_id) do
    Repo.all(
      from(p in SensorPod,
        where: not is_nil(p.pool_id) and p.pool_id != ^pool_id and p.status == "enrolled",
        order_by: [asc: p.name]
      )
    )
  end

  def assign_sensors(%SensorPool{} = pool, sensor_ids, actor, opts \\ []) do
    allow_reassign? = Keyword.get(opts, :allow_reassign?, false)
    sensors = sensors_by_ids(sensor_ids)

    cond do
      sensor_ids == [] ->
        log_pool_failure(pool, actor, "sensor_assigned_to_pool", %{
          reason: "no_sensors_selected",
          sensor_ids: sensor_ids
        })

        {:error, :no_sensors_selected}

      length(sensors) != length(Enum.uniq(sensor_ids)) ->
        log_pool_failure(pool, actor, "sensor_assigned_to_pool", %{
          reason: "sensor_not_found",
          sensor_ids: sensor_ids
        })

        {:error, :sensor_not_found}

      Enum.any?(sensors, &(&1.status != "enrolled")) ->
        log_pool_failure(pool, actor, "sensor_assigned_to_pool", %{
          reason: "sensor_not_enrolled",
          sensor_ids: sensor_ids
        })

        {:error, :sensor_not_enrolled}

      not allow_reassign? and Enum.any?(sensors, &(!is_nil(&1.pool_id) and &1.pool_id != pool.id)) ->
        log_pool_failure(pool, actor, "sensor_assigned_to_pool", %{
          reason: "sensor_already_assigned",
          sensor_ids: sensor_ids
        })

        {:error, :sensor_already_assigned}

      true ->
        assign_sensors_multi(pool, sensors, actor)
    end
  end

  def remove_sensors(%SensorPool{} = pool, sensor_ids, actor) do
    sensors = sensors_by_ids(sensor_ids)

    cond do
      sensor_ids == [] ->
        log_pool_failure(pool, actor, "sensor_removed_from_pool", %{
          reason: "no_sensors_selected",
          sensor_ids: sensor_ids
        })

        {:error, :no_sensors_selected}

      length(sensors) != length(Enum.uniq(sensor_ids)) ->
        log_pool_failure(pool, actor, "sensor_removed_from_pool", %{
          reason: "sensor_not_found",
          sensor_ids: sensor_ids
        })

        {:error, :sensor_not_found}

      Enum.any?(sensors, &(&1.pool_id != pool.id)) ->
        log_pool_failure(pool, actor, "sensor_removed_from_pool", %{
          reason: "sensor_not_in_pool",
          sensor_ids: sensor_ids
        })

        {:error, :sensor_not_in_pool}

      true ->
        remove_sensors_multi(pool, sensors, actor)
    end
  end

  def update_pool_config(%SensorPool{} = pool, attrs, actor) do
    old = config_snapshot(pool)
    changeset = SensorPool.config_update_changeset(pool, attrs, actor_name(actor))

    Multi.new()
    |> Multi.update(:pool, changeset)
    |> Audit.append_multi(fn %{pool: updated} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "pool_config_updated",
        target_type: "pool",
        target_id: updated.id,
        result: "success",
        detail: %{old: old, new: config_snapshot(updated), auto_push: false}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{pool: updated}} ->
        broadcast_pool(updated.id, {:pool_config_updated, updated.id})
        {:ok, updated}

      {:error, :pool, changeset, _changes} ->
        log_pool_failure(pool, actor, "pool_config_updated", %{reason: "validation_failed"})
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def member_count(pool_id) do
    Repo.aggregate(from(p in SensorPod, where: p.pool_id == ^pool_id), :count, :id)
  end

  def pool_name(nil), do: nil

  def pool_name(pool_id) do
    Repo.one(from(p in SensorPool, where: p.id == ^pool_id, select: p.name))
  end

  def pool_name_map do
    Repo.all(from(p in SensorPool, select: {p.id, p.name}))
    |> Map.new()
  end

  def list_pool_deployments(pool_id, opts \\ []) do
    page = max(to_int(Keyword.get(opts, :page, 1)), 1)
    page_size = max(to_int(Keyword.get(opts, :page_size, 25)), 1)

    query =
      from(a in AuditEntry,
        where:
          a.target_type == "pool" and a.target_id == ^pool_id and a.action in ^@deployment_actions,
        order_by: [desc: a.timestamp]
      )

    %{
      entries: query |> limit(^page_size) |> offset(^((page - 1) * page_size)) |> Repo.all(),
      page: page,
      page_size: page_size,
      total_count: Repo.aggregate(query, :count, :id)
    }
  end

  defp assign_sensors_multi(pool, sensors, actor) do
    multi =
      Enum.reduce(sensors, Multi.new(), fn sensor, multi ->
        previous_pool_id = sensor.pool_id

        multi
        |> Multi.update({:sensor, sensor.id}, Ecto.Changeset.change(sensor, pool_id: pool.id))
        |> Audit.append_multi({:audit, sensor.id}, fn _changes ->
          %{
            actor: actor_name(actor),
            actor_type: "user",
            action: "sensor_assigned_to_pool",
            target_type: "sensor_pod",
            target_id: sensor.id,
            result: "success",
            detail: %{
              sensor_name: sensor.name,
              previous_pool_id: previous_pool_id,
              new_pool_id: pool.id,
              pool_name: pool.name
            }
          }
        end)
      end)

    multi
    |> Audit.append_multi(:pool_audit, fn _changes ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "sensor_assigned_to_pool",
        target_type: "pool",
        target_id: pool.id,
        result: "success",
        detail: %{sensor_count: length(sensors), sensor_ids: Enum.map(sensors, & &1.id)}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, _changes} ->
        broadcast_membership(
          pool.id,
          sensors,
          {:sensors_assigned, pool.id, Enum.map(sensors, & &1.id)}
        )

        {:ok, length(sensors)}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  defp remove_sensors_multi(pool, sensors, actor) do
    multi =
      Enum.reduce(sensors, Multi.new(), fn sensor, multi ->
        multi
        |> Multi.update({:sensor, sensor.id}, Ecto.Changeset.change(sensor, pool_id: nil))
        |> Audit.append_multi({:audit, sensor.id}, fn _changes ->
          %{
            actor: actor_name(actor),
            actor_type: "user",
            action: "sensor_removed_from_pool",
            target_type: "sensor_pod",
            target_id: sensor.id,
            result: "success",
            detail: %{sensor_name: sensor.name, previous_pool_id: pool.id, pool_name: pool.name}
          }
        end)
      end)

    multi
    |> Audit.append_multi(:pool_audit, fn _changes ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "sensor_removed_from_pool",
        target_type: "pool",
        target_id: pool.id,
        result: "success",
        detail: %{sensor_count: length(sensors), sensor_ids: Enum.map(sensors, & &1.id)}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, _changes} ->
        broadcast_membership(
          pool.id,
          sensors,
          {:sensors_removed, pool.id, Enum.map(sensors, & &1.id)}
        )

        {:ok, length(sensors)}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  defp member_counts do
    Repo.all(from(p in SensorPod, group_by: p.pool_id, select: {p.pool_id, count(p.id)}))
    |> Enum.reject(fn {pool_id, _count} -> is_nil(pool_id) end)
    |> Map.new()
  end

  defp status_counts do
    Repo.all(
      from(p in SensorPod,
        group_by: [p.pool_id, p.status],
        select: {p.pool_id, p.status, count(p.id)}
      )
    )
    |> Enum.reduce(%{}, fn
      {nil, _status, _count}, acc ->
        acc

      {pool_id, status, count}, acc ->
        update_in(acc, [pool_id], &Map.put(&1 || %{}, status, count))
    end)
  end

  defp sensors_by_ids(sensor_ids) do
    ids = Enum.uniq(sensor_ids)
    Repo.all(from(p in SensorPod, where: p.id in ^ids))
  end

  defp config_snapshot(pool) do
    Map.take(pool, [
      :capture_mode,
      :pcap_ring_size_mb,
      :pre_alert_window_sec,
      :post_alert_window_sec,
      :alert_severity_threshold,
      :config_version,
      :config_updated_at,
      :config_updated_by
    ])
  end

  defp log_pool_failure(pool, actor, action, detail) do
    Audit.log(%{
      actor: actor_name(actor),
      actor_type: "user",
      action: action,
      target_type: "pool",
      target_id: pool.id,
      result: "failure",
      detail: Map.put(detail, :pool_name, pool.name)
    })
  end

  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor), do: actor
  defp actor_name(_actor), do: "system"

  defp broadcast_pools(message),
    do: Phoenix.PubSub.broadcast(ConfigManager.PubSub, "pools", message)

  defp broadcast_pool(pool_id, message),
    do: Phoenix.PubSub.broadcast(ConfigManager.PubSub, "pool:#{pool_id}", message)

  defp broadcast_membership(pool_id, sensors, message) do
    broadcast_pools({:pool_membership_changed, pool_id})
    broadcast_pool(pool_id, message)

    Enum.each(sensors, fn sensor ->
      Phoenix.PubSub.broadcast(
        ConfigManager.PubSub,
        ConfigManager.Health.Registry.pod_topic(sensor.name),
        {:pool_assignment_changed, sensor.id, pool_id}
      )
    end)
  end

  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) do
    case Integer.parse(to_string(value)) do
      {int, _} -> int
      :error -> 1
    end
  end
end
