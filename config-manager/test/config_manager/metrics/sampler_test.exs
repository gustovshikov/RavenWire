defmodule ConfigManager.Metrics.SamplerTest do
  use ConfigManager.DataCase, async: false
  use PropCheck

  alias ConfigManager.Health.Registry
  alias ConfigManager.Metrics.{MetricSnapshot, Sampler}
  alias ConfigManager.{Repo, SensorPod}

  setup do
    Repo.delete_all(MetricSnapshot)
    :ok
  end

  test "extract_snapshots writes only available HealthReport metrics" do
    pod = insert_sensor!("metrics-sampler-extract")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    previous = health_report(pod.name, 1_000, received: 100, dropped: 0)
    current = health_report(pod.name, 61_000, received: 220, dropped: 10)

    snapshots = Sampler.extract_snapshots(pod, current, previous, now)
    metric_types = Enum.map(snapshots, & &1.metric_type)

    assert "packets_received_rate" in metric_types
    assert "drop_percent" in metric_types
    assert "cpu_percent" in metric_types
    assert "memory_bytes" in metric_types
    assert "pcap_disk_used_percent" in metric_types
    assert "clock_offset_ms" in metric_types
    refute "vector_records_per_sec" in metric_types
    refute "sink_buffer_used_percent" in metric_types

    refute snapshots
           |> Enum.map(&Jason.encode!(&1.metadata))
           |> Enum.any?(&String.contains?(&1, "BEGIN CERTIFICATE"))
  end

  test "sampler reads registry, writes snapshots, and broadcasts updates" do
    pod = insert_sensor!("metrics-sampler-live")
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_metrics:#{pod.id}")

    Registry.update_pod(pod.name, health_report(pod.name, 120_000, received: 100, dropped: 2))
    :sys.get_state(Registry)

    {:ok, sampler} = start_supervised({Sampler, name: :metrics_sampler_test, schedule?: false})
    assert :ok = Sampler.sample_once(sampler)

    pod_id = pod.id
    assert_receive {:metrics_updated, ^pod_id}, 1_000
    assert Repo.aggregate(MetricSnapshot, :count, :id) > 0
  end

  test "retention floor is enforced outside tests but configurable in tests" do
    assert Sampler.validated_retention_hours(1, :prod) == 72
    assert Sampler.validated_retention_hours(1, :test) == 1
  end

  property "series keys are deterministic and whitespace-free", [:verbose, numtests: 60] do
    forall code <- integer(0, 10_000) do
      input = "Container #{code} / Zeek"
      first = Sampler.series_key("container", input)
      second = Sampler.series_key("container", input)
      first == second and String.starts_with?(first, "container:") and not String.match?(first, ~r/\s/)
    end
  end

  defp health_report(name, timestamp_ms, opts) do
    received = Keyword.fetch!(opts, :received)
    dropped = Keyword.fetch!(opts, :dropped)

    %Health.HealthReport{
      sensor_pod_id: name,
      timestamp_unix_ms: timestamp_ms,
      containers: [
        %Health.ContainerHealth{name: "zeek", state: "running", cpu_percent: 12.5, memory_bytes: 200_000_000}
      ],
      capture: %Health.CaptureStats{
        consumers: %{
          "zeek" => %Health.ConsumerStats{
            packets_received: received,
            packets_dropped: dropped,
            drop_percent: 1.0
          }
        }
      },
      storage: %Health.StorageStats{path: "/sensor/pcap", used_percent: 42.0},
      clock: %Health.ClockStats{offset_ms: 12, synchronized: true, source: "ntp"}
    }
  end

  defp insert_sensor!(name) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "BEGIN CERTIFICATE\nsecret\nEND CERTIFICATE",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: now,
      enrolled_by: "tester"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(%{
      status: "enrolled",
      cert_serial: "#{name}-serial",
      cert_expires_at: DateTime.add(now, 7 * 24 * 60 * 60, :second)
    })
    |> Repo.update!()
  end
end
