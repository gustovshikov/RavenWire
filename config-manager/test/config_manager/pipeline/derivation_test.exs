defmodule ConfigManager.Pipeline.DerivationTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Pipeline.Derivation

  @now ~U[2026-06-04 12:00:00Z]

  test "derives canonical topology with deterministic dynamic capture consumers" do
    pipeline =
      report()
      |> Derivation.derive_sensor_pipeline(sensor(), opts())

    segment_ids = Enum.map(pipeline.segments, & &1.id)

    assert segment_ids == [
             "mirror_port",
             "af_packet",
             "zeek",
             "suricata",
             "pcap_ring",
             "capture_consumer:alpha-consumer",
             "capture_consumer:custom-consumer",
             "vector",
             "forwarding_sinks"
           ]

    connector_ids = Enum.map(pipeline.connectors, & &1.id)
    assert "mirror_port->af_packet" in connector_ids
    assert "af_packet->capture_consumer:alpha-consumer" in connector_ids
    assert "capture_consumer:custom-consumer->vector" in connector_ids
    assert "vector->forwarding_sinks" in connector_ids
  end

  test "missing health report renders health-derived segments as no data" do
    pipeline = Derivation.derive_sensor_pipeline(nil, sensor(%{status: "pending"}), opts())

    assert pipeline.reporting == false
    assert Enum.all?(pipeline.segments, &(&1.state == :no_data))
    assert Enum.map(pipeline.status_banners, & &1.kind) == [:no_health, :pending]
  end

  test "zero throughput is preserved as real telemetry" do
    stats = %Health.ConsumerStats{throughput_bps: 0, packets_received: 0}
    report = report(%{capture: %Health.CaptureStats{consumers: %{"zeek" => stats}}})

    pipeline = Derivation.derive_sensor_pipeline(report, sensor(), opts())
    connector = Enum.find(pipeline.connectors, &(&1.id == "af_packet->zeek"))

    assert connector.throughput_bps == 0
    assert connector.throughput_label == "0 bps"
    assert connector.flow_state == :idle
    refute Enum.any?(pipeline.segments, &(&1.state == :failed))
  end

  test "vector input record rates drive analysis-to-vector connector flow" do
    report =
      report(%{
        vector: %Health.VectorStats{
          input_records_per_sec: %{"zeek" => 25.0, "suricata" => 0.0},
          total_records_per_sec: 25.0,
          disk_buffer_util_pct: 12.5,
          sink_connectivity: %{"splunk_hec" => "connected"}
        }
      })

    pipeline = Derivation.derive_sensor_pipeline(report, sensor(), opts())
    zeek_connector = Enum.find(pipeline.connectors, &(&1.id == "zeek->vector"))
    suricata_connector = Enum.find(pipeline.connectors, &(&1.id == "suricata->vector"))
    pcap_connector = Enum.find(pipeline.connectors, &(&1.id == "pcap_ring->vector"))
    vector = Enum.find(pipeline.segments, &(&1.id == "vector"))

    assert zeek_connector.throughput_bps == nil
    assert zeek_connector.record_rate_per_sec == 25.0
    assert zeek_connector.throughput_label == "25 rec/s"
    assert zeek_connector.flow_state == :flowing
    assert zeek_connector.speed_tier == :kbps

    assert suricata_connector.record_rate_per_sec == 0.0
    assert suricata_connector.throughput_label == "0 rec/s"
    assert suricata_connector.flow_state == :idle
    assert suricata_connector.speed_tier == :zero

    assert pcap_connector.record_rate_per_sec == nil
    assert pcap_connector.flow_state == :unknown

    assert vector.metrics.record_rate_per_sec == 25.0
    assert vector.metrics.record_rate == "25 rec/s"
    assert vector.tooltip.total_records_per_sec == "25 rec/s"

    vector_summary = Enum.find(pipeline.summary_rows, &(&1.segment == "Vector"))
    assert vector_summary.throughput == "25 rec/s"

    assert vector.tooltip.input_records_per_sec == %{
             "zeek" => "25 rec/s",
             "suricata" => "0 rec/s"
           }

    assert vector.tooltip.sink_connectivity == %{"splunk_hec" => "connected"}
  end

  test "health protobuf accepts app-native process telemetry fields" do
    stats = %Health.ConsumerStats{
      process_throughput_bps: 1600.0,
      process_packets_per_sec: 8.0,
      process_drop_percent: 2.5,
      process_telemetry_source: "suricata eve stats"
    }

    decoded = stats |> Health.ConsumerStats.encode() |> Health.ConsumerStats.decode()

    assert decoded.process_throughput_bps == 1600.0
    assert decoded.process_packets_per_sec == 8.0
    assert decoded.process_drop_percent == 2.5
    assert decoded.process_telemetry_source == "suricata eve stats"
  end

  test "process telemetry drives AF_PACKET to analysis branch labels without double counting NIC ingress" do
    capture = %Health.CaptureStats{
      consumers: %{
        "zeek" => %Health.ConsumerStats{
          throughput_bps: 2_000_000,
          packets_received: 1_000,
          drop_percent: 0.0,
          process_throughput_bps: 800_000,
          process_packets_per_sec: 80.0,
          process_drop_percent: 0.1,
          process_telemetry_source: "zeek stats.log"
        },
        "suricata" => %Health.ConsumerStats{
          throughput_bps: 2_000_000,
          packets_received: 1_000,
          drop_percent: 0.0,
          process_throughput_bps: 1_200_000,
          process_packets_per_sec: 120.0,
          process_drop_percent: 0.2,
          process_telemetry_source: "suricata eve stats"
        }
      }
    }

    pipeline = report(%{capture: capture}) |> Derivation.derive_sensor_pipeline(sensor(), opts())

    mirror_connector = Enum.find(pipeline.connectors, &(&1.id == "mirror_port->af_packet"))
    zeek_connector = Enum.find(pipeline.connectors, &(&1.id == "af_packet->zeek"))
    suricata_connector = Enum.find(pipeline.connectors, &(&1.id == "af_packet->suricata"))
    zeek = Enum.find(pipeline.segments, &(&1.id == "zeek"))
    suricata = Enum.find(pipeline.segments, &(&1.id == "suricata"))
    zeek_summary = Enum.find(pipeline.summary_rows, &(&1.segment == "Zeek"))
    suricata_summary = Enum.find(pipeline.summary_rows, &(&1.segment == "Suricata"))

    assert mirror_connector.throughput_bps == 2_000_000
    assert mirror_connector.throughput_label == "2.0 Mbps"

    assert zeek_connector.throughput_bps == 800_000
    assert zeek_connector.throughput_label == "800.0 Kbps"
    assert zeek_connector.flow_state == :flowing

    assert suricata_connector.throughput_bps == 1_200_000
    assert suricata_connector.throughput_label == "1.2 Mbps"
    assert suricata_connector.flow_state == :flowing

    assert zeek.metrics.throughput_bps == 800_000
    assert zeek.metrics.throughput == "800.0 Kbps"
    assert zeek.metrics.process_telemetry_source == "zeek stats.log"
    assert zeek.tooltip.telemetry_source == "zeek stats.log"
    assert zeek.tooltip.process_packets_per_sec == 80.0

    assert suricata.metrics.throughput_bps == 1_200_000
    assert suricata.metrics.process_telemetry_source == "suricata eve stats"
    assert suricata.tooltip.telemetry_source == "suricata eve stats"

    assert zeek_summary.throughput == "800.0 Kbps"
    assert zeek_summary.details == "container running; telemetry zeek stats.log"
    assert suricata_summary.throughput == "1.2 Mbps"
    assert suricata_summary.details == "container running; telemetry suricata eve stats"
  end

  test "analysis branch throughput falls back to NIC-derived value when process telemetry is missing" do
    capture = %Health.CaptureStats{
      consumers: %{
        "zeek" => %Health.ConsumerStats{
          throughput_bps: 2_000_000,
          packets_received: 1_000,
          drop_percent: 0.0
        }
      }
    }

    pipeline = report(%{capture: capture}) |> Derivation.derive_sensor_pipeline(sensor(), opts())
    connector = Enum.find(pipeline.connectors, &(&1.id == "af_packet->zeek"))
    zeek = Enum.find(pipeline.segments, &(&1.id == "zeek"))
    zeek_summary = Enum.find(pipeline.summary_rows, &(&1.segment == "Zeek"))

    assert connector.throughput_bps == 2_000_000
    assert connector.throughput_label == "2.0 Mbps"
    assert zeek.metrics.throughput_bps == 2_000_000
    assert zeek.metrics.process_telemetry_source == "NIC fallback"
    assert zeek.tooltip.telemetry_source == "NIC fallback"
    assert zeek_summary.details == "container running; telemetry NIC fallback"
  end

  test "analysis degradation prefers process drop percent when present" do
    running = %Health.ContainerHealth{state: "running", cpu_percent: 20.0}

    healthy_from_process =
      Derivation.derive_analysis_tool(
        "zeek",
        running,
        %Health.ConsumerStats{
          drop_percent: 15.0,
          process_drop_percent: 0.0,
          process_telemetry_source: "zeek stats.log"
        }
      )

    degraded_from_process =
      Derivation.derive_analysis_tool(
        "suricata",
        running,
        %Health.ConsumerStats{
          drop_percent: 0.0,
          process_drop_percent: 6.0,
          process_telemetry_source: "suricata eve stats"
        }
      )

    assert healthy_from_process.state == :healthy
    assert healthy_from_process.metrics.drop_percent == 0.0
    assert degraded_from_process.state == :degraded
    assert degraded_from_process.metrics.drop_percent == 6.0
    assert "Suricata capture drops exceed 5.0%." in degraded_from_process.warnings
  end

  test "missing vector telemetry keeps analysis-to-vector connectors unknown" do
    pipeline = report() |> Derivation.derive_sensor_pipeline(sensor(), opts())
    connector = Enum.find(pipeline.connectors, &(&1.id == "zeek->vector"))

    assert connector.record_rate_per_sec == nil
    assert connector.throughput_label == "—"
    assert connector.flow_state == :unknown
  end

  test "failed vector endpoint stops record-rate connector flow" do
    report =
      report(%{
        containers: [
          %Health.ContainerHealth{name: "systemd-zeek", state: "running", cpu_percent: 20.0},
          %Health.ContainerHealth{name: "systemd-suricata", state: "running", cpu_percent: 20.0},
          %Health.ContainerHealth{
            name: "systemd-pcap-ring-writer",
            state: "running",
            cpu_percent: 20.0
          },
          %Health.ContainerHealth{name: "systemd-vector", state: "stopped", cpu_percent: 0.0}
        ],
        vector: %Health.VectorStats{
          input_records_per_sec: %{"zeek" => 25.0},
          total_records_per_sec: 25.0
        }
      })

    pipeline = Derivation.derive_sensor_pipeline(report, sensor(), opts())
    connector = Enum.find(pipeline.connectors, &(&1.id == "zeek->vector"))

    assert connector.record_rate_per_sec == 25.0
    assert connector.throughput_label == "25 rec/s"
    assert connector.flow_state == :stopped
  end

  test "mirror to AF_PACKET throughput does not double count parallel consumers" do
    capture = %Health.CaptureStats{
      consumers: %{
        "zeek" => %Health.ConsumerStats{
          throughput_bps: 275_600,
          packets_received: 312_622,
          drop_percent: 0.0
        },
        "suricata" => %Health.ConsumerStats{
          throughput_bps: 275_600,
          packets_received: 312_622,
          drop_percent: 0.0
        },
        "pcap_ring_writer" => %Health.ConsumerStats{
          throughput_bps: 0,
          packets_received: 0,
          drop_percent: 0.0
        }
      }
    }

    pipeline = report(%{capture: capture}) |> Derivation.derive_sensor_pipeline(sensor(), opts())

    mirror_connector = Enum.find(pipeline.connectors, &(&1.id == "mirror_port->af_packet"))
    mirror_port = Enum.find(pipeline.segments, &(&1.id == "mirror_port"))
    af_packet = Enum.find(pipeline.segments, &(&1.id == "af_packet"))
    mirror_summary = Enum.find(pipeline.summary_rows, &(&1.segment == "ens16f1"))

    assert mirror_port.label == "ens16f1"
    assert mirror_connector.throughput_bps == 275_600
    assert mirror_connector.throughput_label == "275.6 Kbps"
    assert mirror_port.metrics.ingest_bps == 275_600
    assert mirror_port.metrics.ingest == "275.6 Kbps"
    assert mirror_port.tooltip.nic_receive_ingest == "275.6 Kbps"
    assert mirror_summary.throughput == "275.6 Kbps"
    assert mirror_summary.details == "NIC receive ingest from ens16f1"
    assert af_packet.metrics.aggregate_throughput_bps == 275_600
    assert af_packet.metrics.aggregate_throughput == "275.6 Kbps"
  end

  test "forwarding configuration labels the aggregate node without leaking secrets" do
    {:ok, config} =
      Jason.encode(%{
        "endpoint" => "https://user:p4ssw0rd@example.test/path?token=abc123",
        "authorization" => "Bearer abc123"
      })

    pipeline =
      report()
      |> Derivation.derive_sensor_pipeline(
        sensor(),
        opts(
          forwarding_sinks: [
            %{
              name: "http-output",
              sink_type: "http",
              enabled: true,
              config: config
            }
          ],
          forwarding_summary: %{sink_count: 1, enabled_count: 1, schema_mode: "raw"}
        )
      )

    forwarding = Enum.find(pipeline.segments, &(&1.id == "forwarding_sinks"))
    rendered_data = inspect(forwarding)

    assert forwarding.state == :no_data
    assert rendered_data =~ "http-output"
    assert rendered_data =~ "[redacted]"
    refute rendered_data =~ "p4ssw0rd"
    refute rendered_data =~ "abc123"
    refute rendered_data =~ "Bearer"
  end

  property "AF_PACKET state follows consumer drop and BPF rules", [:verbose, numtests: 80] do
    forall code <- integer(0, 1_000) do
      {capture, expected_state} =
        case rem(code, 4) do
          0 ->
            {%Health.CaptureStats{consumers: %{}}, :no_data}

          1 ->
            {%Health.CaptureStats{
               consumers: %{"zeek" => %Health.ConsumerStats{drop_percent: 5.1}}
             }, :degraded}

          2 ->
            {%Health.CaptureStats{
               consumers: %{"zeek" => %Health.ConsumerStats{bpf_restart_pending: true}}
             }, :pending_reload}

          _ ->
            {%Health.CaptureStats{
               consumers: %{"zeek" => %Health.ConsumerStats{drop_percent: 5.0}}
             }, :healthy}
        end

      Derivation.derive_af_packet(capture).state == expected_state
    end
  end

  property "analysis-tool derivation maps container state and CPU pressure", [
    :verbose,
    numtests: 80
  ] do
    forall code <- integer(0, 1_000) do
      {container, consumer, expected_state} =
        case rem(code, 5) do
          0 ->
            {nil, nil, :no_data}

          1 ->
            {%Health.ContainerHealth{state: "error"}, nil, :failed}

          2 ->
            {%Health.ContainerHealth{state: "stopped"}, nil, :failed}

          3 ->
            {%Health.ContainerHealth{state: "running", cpu_percent: 90.1}, nil, :degraded}

          _ ->
            {%Health.ContainerHealth{state: "running", cpu_percent: 90.0},
             %Health.ConsumerStats{drop_percent: 0.0}, :healthy}
        end

      Derivation.derive_analysis_tool("zeek", container, consumer).state == expected_state
    end
  end

  property "storage thresholds classify warning and critical levels", [:verbose, numtests: 80] do
    forall used_percent <- integer(0, 120) do
      result =
        Derivation.derive_storage_warnings(%Health.StorageStats{used_percent: used_percent / 1})

      expected =
        cond do
          used_percent > 95 -> :critical
          used_percent > 85 -> :warning
          true -> :none
        end

      result.level == expected
    end
  end

  property "staleness handles invalid, current, stale, and future timestamps", [
    :verbose,
    numtests: 80
  ] do
    forall code <- integer(-120, 120) do
      timestamp =
        cond do
          code < -90 -> code
          true -> @now |> DateTime.add(code, :second) |> DateTime.to_unix(:millisecond)
        end

      {stale?, age} = Derivation.check_staleness(timestamp, now: @now, stale_threshold_sec: 60)

      cond do
        code < -90 -> stale? == true and is_nil(age)
        code < -60 -> stale? == true and age > 60
        code < 0 -> stale? == false and age <= 60
        true -> stale? == false and age == 0
      end
    end
  end

  property "worst state ignores no_data when reporting states exist", [:verbose, numtests: 80] do
    forall code <- integer(0, 100) do
      states =
        case rem(code, 6) do
          0 -> [:no_data]
          1 -> [:healthy, :no_data]
          2 -> [:pending_reload, :healthy, :no_data]
          3 -> [:degraded, :healthy]
          4 -> [:failed, :degraded, :healthy]
          _ -> [:disabled, :no_data]
        end

      expected =
        case rem(code, 6) do
          0 -> :no_data
          1 -> :healthy
          2 -> :pending_reload
          3 -> :degraded
          4 -> :failed
          _ -> :disabled
        end

      Derivation.worst_state(states) == expected
    end
  end

  property "pool aggregation counts member segment states", [:verbose, numtests: 40] do
    forall healthy_count <- integer(1, 6) do
      no_data_state = Derivation.derive_sensor_pipeline(nil, sensor(%{name: "offline"}), opts())
      healthy_state = Derivation.derive_sensor_pipeline(report(), sensor(), opts())

      member_states =
        Enum.map(1..healthy_count, fn index ->
          {"sensor-#{index}", "sensor-#{index}", healthy_state}
        end) ++ [{"offline", "offline", no_data_state}]

      aggregate = Derivation.aggregate_pool_pipeline(member_states)
      af_packet = Enum.find(aggregate.segments, &(&1.id == "af_packet"))

      aggregate.total_members == healthy_count + 1 and
        aggregate.reporting_members == healthy_count and
        af_packet.state_counts.healthy == healthy_count and
        af_packet.state_counts.no_data == 1 and
        af_packet.overall_state == :healthy
    end
  end

  property "derivation is deterministic for stable inputs", [:verbose, numtests: 40] do
    forall code <- integer(0, 10_000) do
      sensor = sensor(%{name: "sensor-#{code}"})
      input = report(%{sensor_pod_id: sensor.name})

      Derivation.derive_sensor_pipeline(input, sensor, opts()) ==
        Derivation.derive_sensor_pipeline(input, sensor, opts())
    end
  end

  defp report(attrs \\ %{}) do
    defaults = %{
      sensor_pod_id: "pipeline-sensor",
      timestamp_unix_ms: DateTime.to_unix(@now, :millisecond),
      system: %Health.SystemStats{
        capture_interface: "ens16f1",
        nic_driver: "ixgbe",
        af_packet_available: true
      },
      containers: [
        %Health.ContainerHealth{name: "systemd-zeek", state: "running", cpu_percent: 20.0},
        %Health.ContainerHealth{name: "systemd-suricata", state: "running", cpu_percent: 20.0},
        %Health.ContainerHealth{
          name: "systemd-pcap-ring-writer",
          state: "running",
          cpu_percent: 20.0
        },
        %Health.ContainerHealth{name: "systemd-vector", state: "running", cpu_percent: 20.0}
      ],
      capture: %Health.CaptureStats{
        consumers: %{
          "zeek" => %Health.ConsumerStats{
            packets_received: 100,
            drop_percent: 0.0,
            throughput_bps: 1_000_000
          },
          "suricata" => %Health.ConsumerStats{
            packets_received: 100,
            drop_percent: 0.0,
            throughput_bps: 1_000_000
          },
          "pcap_ring_writer" => %Health.ConsumerStats{
            packets_received: 100,
            drop_percent: 0.0,
            throughput_bps: 1_000_000
          },
          "custom consumer" => %Health.ConsumerStats{
            packets_received: 100,
            drop_percent: 0.0,
            throughput_bps: 1_000_000
          },
          "alpha consumer" => %Health.ConsumerStats{
            packets_received: 100,
            drop_percent: 0.0,
            throughput_bps: 1_000_000
          }
        }
      },
      storage: %Health.StorageStats{
        path: "/var/lib/ravenwire/pcap",
        total_bytes: 1_000_000,
        used_bytes: 500_000,
        used_percent: 50.0
      }
    }

    struct!(Health.HealthReport, Map.merge(defaults, attrs))
  end

  defp sensor(attrs \\ %{}) do
    Map.merge(
      %{
        id: Ecto.UUID.generate(),
        name: "pipeline-sensor",
        status: "enrolled",
        pool_id: nil
      },
      attrs
    )
  end

  defp opts(extra \\ []) do
    Keyword.merge(
      [
        now: @now,
        stale_threshold_sec: 60,
        forwarding_sinks: [],
        forwarding_summary: %{sink_count: 0, enabled_count: 0, schema_mode: nil},
        capture_mode: "full_pcap",
        degradation_reasons: []
      ],
      extra
    )
  end
end
