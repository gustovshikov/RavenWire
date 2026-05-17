defmodule ConfigManager.Deployments.DriftDetector do
  @moduledoc "Computes per-sensor deployment drift for pool desired state."

  import Ecto.Query

  alias ConfigManager.{Repo, SensorPod, SensorPool}

  def compute(%SensorPool{} = pool) do
    pool.id
    |> pool_sensors()
    |> Enum.map(&sensor_drift(&1, pool))
  end

  def compute(pool_id) when is_binary(pool_id) do
    SensorPool
    |> Repo.get!(pool_id)
    |> compute()
  end

  def sensor_drift(%SensorPod{pool_id: nil} = sensor) do
    %{sensor: sensor, status: :never_deployed, domains: []}
  end

  def sensor_drift(%SensorPod{} = sensor) do
    SensorPool
    |> Repo.get!(sensor.pool_id)
    |> then(&sensor_drift(sensor, &1))
  end

  def sensor_drift(%SensorPod{} = sensor, %SensorPool{} = pool) do
    cond do
      never_deployed?(sensor) ->
        %{sensor: sensor, status: :never_deployed, domains: []}

      true ->
        domains = drifted_domains(sensor, pool)
        status = if domains == [], do: :in_sync, else: :drift_detected
        %{sensor: sensor, status: status, domains: domains}
    end
  end

  def summary(results) when is_list(results) do
    counts = Enum.frequencies_by(results, & &1.status)

    %{
      total: length(results),
      in_sync: Map.get(counts, :in_sync, 0),
      drift_detected: Map.get(counts, :drift_detected, 0),
      never_deployed: Map.get(counts, :never_deployed, 0)
    }
  end

  defp pool_sensors(pool_id) do
    Repo.all(
      from(p in SensorPod,
        where: p.pool_id == ^pool_id and p.status == "enrolled",
        order_by: [asc: p.name]
      )
    )
  end

  defp never_deployed?(sensor) do
    is_nil(sensor.last_deployed_config_version) and
      is_nil(sensor.last_deployed_forwarding_version) and
      is_nil(sensor.last_deployed_bpf_version)
  end

  defp drifted_domains(sensor, pool) do
    []
    |> maybe_drift(:capture, sensor.last_deployed_config_version, pool.config_version)
    |> maybe_drift(:forwarding, sensor.last_deployed_forwarding_version, 0)
  end

  defp maybe_drift(domains, _domain, nil, _current), do: domains
  defp maybe_drift(domains, _domain, _deployed, nil), do: domains

  defp maybe_drift(domains, domain, deployed, current) when deployed != current,
    do: [domain | domains]

  defp maybe_drift(domains, _domain, _deployed, _current), do: domains
end
