defmodule ConfigManager.Health.RegistryTest do
  use ExUnit.Case, async: false

  alias ConfigManager.{Repo, SensorPod}
  alias ConfigManager.Health.Registry

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  test "health reports update the enrolled pod last_seen_at" do
    pod_name = "last-seen-pod-#{System.unique_integer([:positive])}"

    Repo.insert!(%SensorPod{
      name: pod_name,
      status: "enrolled",
      cert_serial: "SERIAL",
      cert_expires_at:
        DateTime.add(DateTime.utc_now(), 86_400, :second) |> DateTime.truncate(:second)
    })

    seen_at = ~U[2026-05-03 19:15:30Z]

    Registry.update(pod_name, %Health.HealthReport{
      sensor_pod_id: pod_name,
      timestamp_unix_ms: DateTime.to_unix(seen_at, :millisecond)
    })

    assert_last_seen(pod_name, seen_at)
  end

  test "older health reports do not move last_seen_at backwards" do
    pod_name = "last-seen-order-pod-#{System.unique_integer([:positive])}"
    newer_seen_at = ~U[2026-05-03 19:20:30Z]
    older_seen_at = ~U[2026-05-03 19:10:30Z]

    Repo.insert!(%SensorPod{
      name: pod_name,
      status: "enrolled",
      cert_serial: "SERIAL",
      cert_expires_at:
        DateTime.add(DateTime.utc_now(), 86_400, :second) |> DateTime.truncate(:second),
      last_seen_at: newer_seen_at
    })

    Registry.update(pod_name, %Health.HealthReport{
      sensor_pod_id: pod_name,
      timestamp_unix_ms: DateTime.to_unix(older_seen_at, :millisecond)
    })

    Process.sleep(50)
    assert Repo.get_by!(SensorPod, name: pod_name).last_seen_at == newer_seen_at
  end

  defp assert_last_seen(pod_name, expected) do
    Enum.reduce_while(1..20, nil, fn _, _ ->
      pod = Repo.get_by!(SensorPod, name: pod_name)

      if pod.last_seen_at == expected do
        {:halt, :ok}
      else
        Process.sleep(25)
        {:cont, nil}
      end
    end)

    assert Repo.get_by!(SensorPod, name: pod_name).last_seen_at == expected
  end
end
