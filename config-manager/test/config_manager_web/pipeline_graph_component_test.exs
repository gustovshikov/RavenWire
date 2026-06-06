defmodule ConfigManagerWeb.PipelineGraphComponentTest do
  use ConfigManagerWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias ConfigManagerWeb.PipelineGraphComponent

  test "renders every segment as a focusable node with health state classes" do
    html =
      render_component(&PipelineGraphComponent.sensor_pipeline_graph/1,
        pipeline_state: sensor_pipeline_state(),
        selected_segment_id: "af_packet"
      )

    document = Floki.parse_fragment!(html)
    nodes = Floki.find(document, ".pipeline-node-segment")

    assert length(nodes) == 7
    assert Floki.find(document, ".pipeline-node-ring") == []
    assert Floki.find(document, ".pipeline-node-state-badge") == []

    for label <- [
          "Mirror Port",
          "AF_PACKET",
          "Zeek",
          "Suricata",
          "PCAP Ring",
          "Vector",
          "Forwarding Sinks"
        ] do
      assert html =~ label
    end

    assert html =~ "pipeline-node-state-healthy"
    assert html =~ "pipeline-node-state-degraded"
    assert html =~ "pipeline-node-state-failed"
    assert html =~ "pipeline-node-state-disabled"
    assert html =~ "pipeline-node-state-pending"
    assert html =~ "pipeline-node-state-no-data"

    Enum.each(nodes, fn node ->
      assert attribute(node, "type") == "button"
      assert attribute(node, "phx-click") == "select_segment"
      assert attribute(node, "phx-focus") == "focus_segment"

      assert attribute(node, "phx-value-id") in [
               "mirror_port",
               "af_packet",
               "zeek",
               "suricata",
               "pcap_ring",
               "vector",
               "forwarding_sinks"
             ]

      assert attribute(node, "aria-label") =~
               ~r/(Healthy|Degraded|Failed|Disabled|Pending Reload|No Data)/
    end)

    mirror_node = Floki.find(document, "#pipeline-node-segment-mirror_port") |> List.first()
    mirror_text = Floki.text(mirror_node)

    assert mirror_text =~ "Mirror Port"
    assert mirror_text =~ "2.0 Mbps"
    refute mirror_text =~ "Healthy"
  end

  test "defaults to AF_PACKET selected with the detail drawer collapsed" do
    html =
      render_component(&PipelineGraphComponent.sensor_pipeline_graph/1,
        pipeline_state: sensor_pipeline_state()
      )

    document = Floki.parse_fragment!(html)
    selected = Floki.find(document, "#pipeline-node-segment-af_packet") |> List.first()
    toggle = Floki.find(document, ".pipeline-node-detail-toggle") |> List.first()
    panel = Floki.find(document, "#pipeline-node-detail-panel") |> List.first()

    assert attribute(selected, "aria-pressed") == "true"
    assert attribute(toggle, "aria-expanded") == "false"
    assert Floki.text(toggle) =~ "Show details"
    assert attribute(panel, "aria-hidden") == "true"
    assert Floki.find(document, ".pipeline-node-detail-collapsed") != []
  end

  test "connector paths render without blocking labels" do
    html =
      render_component(&PipelineGraphComponent.sensor_pipeline_graph/1,
        pipeline_state: sensor_pipeline_state(),
        selected_segment_id: "vector"
      )

    document = Floki.parse_fragment!(html)

    assert Floki.find(document, ".pipeline-node-edge-rate") == []
    assert Floki.find(document, ".pipeline-node-edge-secondary") == []

    graph_text =
      document
      |> Floki.find(".pipeline-node-canvas")
      |> Floki.text()

    assert graph_text =~ "2.0 Mbps"
    refute graph_text =~ "1,000 packets"
  end

  test "selected node detail panel renders metrics, warnings, badges, and tooltip data" do
    html =
      render_component(&PipelineGraphComponent.sensor_pipeline_graph/1,
        pipeline_state: sensor_pipeline_state(),
        selected_segment_id: "af_packet"
      )

    document = Floki.parse_fragment!(html)
    selected = Floki.find(document, "#pipeline-node-segment-af_packet") |> List.first()
    panel = Floki.find(document, ".pipeline-node-detail") |> Floki.text()

    assert attribute(selected, "aria-pressed") == "true"
    assert panel =~ "Selected Node"
    assert panel =~ "AF_PACKET"
    assert panel =~ "Degraded"
    assert panel =~ "Aggregate Throughput: 2.0 Mbps"
    assert panel =~ "Max Drop Percent: 7.5"
    assert panel =~ "drops observed"
    assert panel =~ "drop badge"
  end

  defp sensor_pipeline_state do
    %{
      stale: true,
      stale_age_seconds: 90,
      status_banners: [
        %{kind: :pending, label: "Pending Enrollment", message: "Enrollment is pending."}
      ],
      segments: [
        sensor_segment("mirror_port", "Mirror Port", :healthy,
          metrics: %{capture_interface: "ens16f1", throughput: "2.0 Mbps"},
          tooltip: %{capture_interface: "ens16f1"}
        ),
        sensor_segment("af_packet", "AF_PACKET", :degraded,
          metrics: %{aggregate_throughput: "2.0 Mbps", max_drop_percent: 7.5},
          warnings: ["drops observed"],
          badges: [%{kind: :drops, label: "drop badge"}],
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
          tooltip: %{storage_used_label: "87.0% used"}
        ),
        sensor_segment("vector", "Vector", :no_data,
          metrics: %{},
          tooltip: %{forwarding_telemetry: "not available"}
        ),
        sensor_segment("forwarding_sinks", "Forwarding Sinks", :no_data,
          metrics: %{sink_count: 1, enabled_count: 1},
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
        }
      ]
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

  defp connector(source_id, target_id, throughput_label, secondary_label, flow_state, speed_tier) do
    %{
      id: "#{source_id}->#{target_id}",
      source_id: source_id,
      target_id: target_id,
      throughput_label: throughput_label,
      secondary_label: secondary_label,
      flow_state: flow_state,
      speed_tier: speed_tier,
      accessible_summary: "#{source_id} to #{target_id}: #{throughput_label}, #{secondary_label}"
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
