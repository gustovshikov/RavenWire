defmodule ConfigManager.Deployments.DriftPropertyTest do
  @moduledoc "Property coverage for per-sensor deployment drift classification."

  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Deployments.DriftDetector
  alias ConfigManager.{SensorPod, SensorPool}

  property "Property 9: drift computation classifies version tuples correctly",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 2_000) do
      pool = %SensorPool{id: Ecto.UUID.generate(), config_version: rem(code, 5) + 1}

      sensor = %SensorPod{
        id: Ecto.UUID.generate(),
        pool_id: pool.id,
        status: "enrolled",
        last_deployed_config_version: maybe_version(code, 2),
        last_deployed_forwarding_version: maybe_version(code, 3),
        last_deployed_bpf_version: maybe_version(code, 5)
      }

      result = DriftDetector.sensor_drift(sensor, pool)
      {expected_status, expected_domains} = expected_drift(sensor, pool)

      result.status == expected_status and
        MapSet.new(result.domains) == MapSet.new(expected_domains)
    end
  end

  defp maybe_version(code, divisor) do
    if rem(code, divisor) == 0 do
      nil
    else
      rem(div(code, divisor), 5)
    end
  end

  defp expected_drift(sensor, pool) do
    if is_nil(sensor.last_deployed_config_version) and
         is_nil(sensor.last_deployed_forwarding_version) and
         is_nil(sensor.last_deployed_bpf_version) do
      {:never_deployed, []}
    else
      domains =
        []
        |> maybe_domain(:capture, sensor.last_deployed_config_version, pool.config_version)
        |> maybe_domain(:forwarding, sensor.last_deployed_forwarding_version, 0)

      if domains == [] do
        {:in_sync, []}
      else
        {:drift_detected, domains}
      end
    end
  end

  defp maybe_domain(domains, _domain, nil, _current), do: domains

  defp maybe_domain(domains, domain, deployed, current) when deployed != current,
    do: [domain | domains]

  defp maybe_domain(domains, _domain, _deployed, _current), do: domains
end
