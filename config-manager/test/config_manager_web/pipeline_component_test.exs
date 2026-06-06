defmodule ConfigManagerWeb.PipelineComponentTest do
  use ConfigManagerWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias ConfigManagerWeb.PipelineComponent

  test "sensor mode renders visual state palette, banners, tooltips, connectors, and summary table" do
    html =
      render_component(&PipelineComponent.pipeline_visualization/1,
        pipeline_state: sensor_pipeline_state(),
        mode: :sensor
      )

    assert html =~ "Current sensor pipeline state from the latest HealthReport."
    assert html =~ "Revoked Sensor"
    assert html =~ "Pending Enrollment"
    assert html =~ "No Health Data"
    assert html =~ "Stale"
    assert html =~ "Last report was 90 seconds ago."

    assert html =~ "pipeline-state-healthy"
    assert html =~ "pipeline-state-degraded"
    assert html =~ "pipeline-state-failed"
    assert html =~ "pipeline-state-disabled"
    assert html =~ "pipeline-state-pending"
    assert html =~ "pipeline-state-no-data"
    assert html =~ "pipeline-segment-stale"

    assert html =~ "flow-state-flowing flow-speed-mbps"
    assert html =~ "flow-state-degraded flow-speed-kbps"
    assert html =~ "flow-state-stopped flow-speed-unknown"
    assert html =~ "pipeline-connector-flow"
    assert html =~ "2.0 Mbps"
    assert html =~ "1,000 packets"

    assert html =~ "Pipeline Summary"
    assert html =~ "Throughput"
    assert html =~ "drops observed"
    assert html =~ "Details"
    assert html =~ "Capture Interface"
    assert html =~ "ens16f1"
  end

  test "pool mode renders aggregate state counts, reporting count, and member links" do
    html =
      render_component(&PipelineComponent.pipeline_visualization/1,
        pipeline_state: pool_pipeline_state(),
        mode: :pool,
        pool_member_links: [
          %{label: "sensor-a", href: "/sensors/sensor-a-id/pipeline"},
          %{label: "sensor-b", href: "/sensors/sensor-b-id/pipeline"}
        ]
      )

    assert html =~ "Aggregate pipeline health for this pool."
    assert html =~ "reporting"
    assert html =~ "Member Sensor Pipelines"
    assert html =~ ~s(href="/sensors/sensor-a-id/pipeline")
    assert html =~ ~s(href="/sensors/sensor-b-id/pipeline")
    assert html =~ "1 healthy"
    assert html =~ "1 degraded"
    assert html =~ "1 no data"
    assert html =~ "Overall"
    assert html =~ "No Data"
  end

  test "rendered markup exposes keyboard focus and accessible labels for segments, connectors, tables, and tooltips" do
    html =
      render_component(&PipelineComponent.pipeline_visualization/1,
        pipeline_state: sensor_pipeline_state(),
        mode: :sensor
      )

    document = Floki.parse_fragment!(html)
    segments = Floki.find(document, ".pipeline-segment")
    connectors = Floki.find(document, ".pipeline-connector")
    tooltips = Floki.find(document, ".pipeline-tooltip")

    assert length(segments) == 7
    assert length(connectors) == 3
    assert length(tooltips) == 7

    Enum.each(segments, fn segment ->
      assert attribute(segment, "tabindex") == "0"

      assert attribute(segment, "aria-label") =~
               ~r/(Healthy|Degraded|Failed|Disabled|Pending Reload|No Data)/
    end)

    Enum.each(connectors, fn connector ->
      assert attribute(connector, "tabindex") == "0"
      assert attribute(connector, "aria-label") =~ ~r/to/
      assert attribute(connector, "aria-label") =~ ~r/(bps|—)/
    end)

    Enum.each(tooltips, fn tooltip ->
      assert attribute(tooltip, "phx-hook") == "PipelineTooltip"
      assert attribute(tooltip, "aria-label") =~ "Details for "
      assert Floki.find(tooltip, "summary") |> Floki.text() == "Details"
      assert Floki.find(tooltip, "dl") != []
    end)

    assert Floki.find(document, ".pipeline-summary[aria-label=\"Pipeline summary table\"] table") !=
             []

    assert Floki.find(document, ".pipeline-summary th") |> Enum.map(&Floki.text/1) == [
             "Segment",
             "State",
             "Throughput",
             "Details"
           ]
  end

  defp sensor_pipeline_state do
    %{
      stale: true,
      stale_age_seconds: 90,
      reporting: true,
      reporting_members: 0,
      total_members: 0,
      status_banners: [
        %{kind: :revoked, label: "Revoked Sensor", message: "This sensor has been revoked."},
        %{kind: :pending, label: "Pending Enrollment", message: "Enrollment is pending."},
        %{kind: :no_health, label: "No Health Data", message: "This sensor is not reporting."}
      ],
      segments: [
        sensor_segment("mirror_port", "Mirror Port", :healthy,
          metrics: %{capture_interface: "ens16f1", throughput: "2.0 Mbps"},
          tooltip: %{
            capture_interface: "ens16f1",
            telemetry_scope: "Local capture interface only."
          }
        ),
        sensor_segment("af_packet", "AF_PACKET", :degraded,
          metrics: %{aggregate_throughput: "2.0 Mbps", max_drop_percent: 7.5},
          warnings: ["drops observed"],
          tooltip: %{aggregate_throughput: "2.0 Mbps", max_drop_percent: 7.5}
        ),
        sensor_segment("zeek", "Zeek", :failed,
          metrics: %{container_state: "stopped"},
          tooltip: %{container_state: "stopped"}
        ),
        sensor_segment("suricata", "Suricata", :disabled,
          metrics: %{container_state: "disabled"},
          tooltip: %{container_state: "disabled"}
        ),
        sensor_segment("pcap_ring", "PCAP Ring", :pending_reload,
          metrics: %{storage_used_label: "87.0% used"},
          badges: [%{kind: :storage_warning, label: "storage warning"}],
          tooltip: %{storage: %{storage_used_label: "87.0% used"}}
        ),
        sensor_segment("vector", "Vector", :no_data,
          metrics: %{},
          tooltip: %{forwarding_telemetry: "not available"}
        ),
        sensor_segment("forwarding_sinks", "Forwarding Sinks", :no_data,
          metrics: %{sink_count: 1, enabled_count: 1},
          badges: [%{kind: :no_data, label: "runtime no data"}],
          tooltip: %{runtime_telemetry: "not available"}
        )
      ],
      connectors: [
        connector("mirror_port", "af_packet", "2.0 Mbps", "1,000 packets", :flowing, :mbps),
        connector("af_packet", "zeek", "80.0 Kbps", nil, :degraded, :kbps),
        connector("zeek", "vector", "—", nil, :stopped, :unknown)
      ],
      summary_rows: [
        %{segment: "Mirror Port", state: "Healthy", throughput: "2.0 Mbps", details: "ens16f1"},
        %{
          segment: "AF_PACKET",
          state: "Degraded",
          throughput: "2.0 Mbps",
          details: "drops observed"
        },
        %{segment: "Zeek", state: "Failed", throughput: "—", details: "stopped"},
        %{segment: "Suricata", state: "Disabled", throughput: "—", details: "disabled"},
        %{
          segment: "PCAP Ring",
          state: "Pending Reload",
          throughput: "—",
          details: "storage warning"
        },
        %{segment: "Vector", state: "No Data", throughput: "—", details: "not available"},
        %{
          segment: "Forwarding Sinks",
          state: "No Data",
          throughput: "—",
          details: "runtime no data"
        }
      ]
    }
  end

  defp pool_pipeline_state do
    segments =
      [
        pool_segment("mirror_port", "Mirror Port", :healthy, %{
          healthy: 1,
          degraded: 0,
          failed: 0,
          pending_reload: 0,
          disabled: 0,
          no_data: 0
        }),
        pool_segment("af_packet", "AF_PACKET", :degraded, %{
          healthy: 0,
          degraded: 1,
          failed: 0,
          pending_reload: 0,
          disabled: 0,
          no_data: 0
        }),
        pool_segment("zeek", "Zeek", :no_data, %{
          healthy: 0,
          degraded: 0,
          failed: 0,
          pending_reload: 0,
          disabled: 0,
          no_data: 1
        }),
        pool_segment("suricata", "Suricata", :disabled, %{
          healthy: 0,
          degraded: 0,
          failed: 0,
          pending_reload: 0,
          disabled: 1,
          no_data: 0
        }),
        pool_segment("pcap_ring", "PCAP Ring", :pending_reload, %{
          healthy: 0,
          degraded: 0,
          failed: 0,
          pending_reload: 1,
          disabled: 0,
          no_data: 0
        }),
        pool_segment("vector", "Vector", :failed, %{
          healthy: 0,
          degraded: 0,
          failed: 1,
          pending_reload: 0,
          disabled: 0,
          no_data: 0
        }),
        pool_segment("forwarding_sinks", "Forwarding Sinks", :no_data, %{
          healthy: 0,
          degraded: 0,
          failed: 0,
          pending_reload: 0,
          disabled: 0,
          no_data: 1
        })
      ]

    %{
      reporting_members: 1,
      total_members: 3,
      status_banners: [],
      segments: segments,
      connectors: [
        connector("mirror_port", "af_packet", "—", nil, :unknown, :unknown),
        connector("af_packet", "zeek", "—", nil, :unknown, :unknown)
      ],
      summary_rows: Enum.map(segments, &pool_summary_row/1)
    }
  end

  defp sensor_segment(id, label, state, opts) do
    %{
      id: id,
      label: label,
      state: state,
      metrics: Keyword.get(opts, :metrics, %{}),
      warnings: Keyword.get(opts, :warnings, []),
      badges: Keyword.get(opts, :badges, []),
      tooltip: Keyword.get(opts, :tooltip, %{}),
      accessible_summary: "#{label}: #{human_state(state)}."
    }
  end

  defp pool_segment(id, label, overall_state, counts) do
    %{
      id: id,
      label: label,
      overall_state: overall_state,
      state_counts: counts,
      badges: [],
      warnings: [],
      tooltip: %{overall_state: human_state(overall_state)},
      accessible_summary: "#{label}: #{human_state(overall_state)} overall."
    }
  end

  defp connector(source_id, target_id, throughput_label, secondary_label, flow_state, speed_tier) do
    %{
      id: "#{source_id}->#{target_id}",
      source_id: source_id,
      target_id: target_id,
      throughput_label: throughput_label,
      secondary_label: secondary_label,
      flow_state: flow_state,
      speed_tier: speed_tier,
      accessible_summary: "#{source_id} to #{target_id}: #{throughput_label}"
    }
  end

  defp pool_summary_row(segment) do
    counts = segment.state_counts

    %{
      segment: segment.label,
      overall_state: human_state(segment.overall_state),
      healthy: counts.healthy,
      degraded: counts.degraded,
      failed: counts.failed,
      pending_reload: counts.pending_reload,
      disabled: counts.disabled,
      no_data: counts.no_data
    }
  end

  defp attribute(node, name) do
    node
    |> Floki.attribute(name)
    |> List.first()
  end

  defp human_state(:pending_reload), do: "Pending Reload"

  defp human_state(state) do
    state
    |> to_string()
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map_join(" ", &String.capitalize/1)
  end
end
