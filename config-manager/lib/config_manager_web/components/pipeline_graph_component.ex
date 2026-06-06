defmodule ConfigManagerWeb.PipelineGraphComponent do
  @moduledoc "Node graph components for the sensor pipeline visualization."

  use Phoenix.Component

  @state_styles %{
    healthy: %{class: "pipeline-node-state-healthy", label: "Healthy"},
    degraded: %{class: "pipeline-node-state-degraded", label: "Degraded"},
    failed: %{class: "pipeline-node-state-failed", label: "Failed"},
    disabled: %{class: "pipeline-node-state-disabled", label: "Disabled"},
    pending_reload: %{
      class: "pipeline-node-state-pending",
      label: "Pending Reload"
    },
    no_data: %{class: "pipeline-node-state-no-data", label: "No Data"}
  }

  attr(:pipeline_state, :map, required: true)
  attr(:selected_segment_id, :string, default: nil)
  attr(:detail_panel_open, :boolean, default: false)

  def sensor_pipeline_graph(assigns) do
    segments = Map.get(assigns.pipeline_state, :segments, [])
    nodes = graph_nodes(segments, assigns.selected_segment_id)
    node_map = Map.new(nodes, &{&1.id, &1})
    selected_segment = selected_segment(segments, assigns.selected_segment_id)

    assigns =
      assigns
      |> assign(:nodes, nodes)
      |> assign(:edges, graph_edges(Map.get(assigns.pipeline_state, :connectors, []), node_map))
      |> assign(:selected_segment, selected_segment)
      |> assign(:selected_style, state_style(segment_state(selected_segment)))
      |> assign(:selected_metrics, detail_metrics(selected_segment))
      |> assign(:selected_rows, tooltip_rows(Map.get(selected_segment || %{}, :tooltip, %{})))
      |> assign(:status_banners, Map.get(assigns.pipeline_state, :status_banners, []))
      |> assign(:stale, Map.get(assigns.pipeline_state, :stale, false))
      |> assign(:stale_age_seconds, Map.get(assigns.pipeline_state, :stale_age_seconds))
      |> assign(:summary_rows, Map.get(assigns.pipeline_state, :summary_rows, []))
      |> assign(:detail_panel_open, assigns.detail_panel_open)

    ~H"""
    <section class="pipeline-node-card" aria-labelledby="pipeline-node-title">
      <div class="pipeline-node-heading">
        <div>
          <h2 id="pipeline-node-title">Live Sensor Node Graph</h2>
          <p>Real-time sensor pipeline state from the latest HealthReport.</p>
        </div>
        <div class="pipeline-node-legend" aria-label="Health state legend">
          <span class="pipeline-node-legend-item pipeline-node-state-healthy">Healthy</span>
          <span class="pipeline-node-legend-item pipeline-node-state-degraded">Degraded</span>
          <span class="pipeline-node-legend-item pipeline-node-state-failed">Failed</span>
          <span class="pipeline-node-legend-item pipeline-node-state-no-data">No Data</span>
        </div>
      </div>

      <div :for={banner <- @status_banners} class={"pipeline-banner pipeline-banner-#{banner.kind}"}>
        <strong><%= banner.label %></strong>
        <span><%= banner.message %></span>
      </div>

      <div :if={@stale} class="pipeline-banner pipeline-banner-stale">
        <strong>Stale</strong>
        <span><%= stale_label(@stale_age_seconds) %></span>
      </div>

      <div class={[
        "pipeline-node-shell",
        @detail_panel_open && "pipeline-node-detail-open",
        !@detail_panel_open && "pipeline-node-detail-collapsed"
      ]}>
        <button
          type="button"
          class="pipeline-node-detail-toggle"
          phx-click="toggle_detail_panel"
          aria-controls="pipeline-node-detail-panel"
          aria-expanded={to_string(@detail_panel_open)}
        >
          <%= if @detail_panel_open, do: "Hide details", else: "Show details" %>
        </button>

        <div class="pipeline-node-scroll">
          <div class="pipeline-node-canvas" role="group" aria-label="Sensor pipeline node graph">
            <svg
              class="pipeline-node-svg"
              viewBox="0 0 100 100"
              preserveAspectRatio="none"
              role="img"
              aria-label="Pipeline connector paths"
              focusable="false"
            >
              <g
                :for={edge <- @edges}
                class={edge.class}
                aria-label={edge.accessible_summary}
              >
                <path class="pipeline-node-edge-base" d={edge.path} />
                <path :if={edge.animated} class="pipeline-node-edge-flow" d={edge.path} />
              </g>
            </svg>

            <button
              :for={node <- @nodes}
              id={"pipeline-node-segment-#{dom_id(node.id)}"}
              type="button"
              class={["pipeline-node-segment", node.state_class, node.selected && "pipeline-node-selected"]}
              style={node.style}
              phx-click="select_segment"
              phx-focus="focus_segment"
              phx-value-id={node.id}
              aria-label={node.accessible_summary}
              aria-pressed={to_string(node.selected)}
            >
              <span class="pipeline-node-label">
                <strong><%= node.label %></strong>
                <span><%= node.throughput %></span>
              </span>
            </button>
          </div>
        </div>

        <aside
          id="pipeline-node-detail-panel"
          class="pipeline-node-detail"
          aria-labelledby="pipeline-node-detail-title"
          aria-live="polite"
          aria-hidden={to_string(!@detail_panel_open)}
        >
          <div :if={@selected_segment}>
            <div class="pipeline-node-detail-head">
              <div>
                <p class="pipeline-node-detail-kicker">Selected Node</p>
                <h3 id="pipeline-node-detail-title"><%= @selected_segment.label %></h3>
              </div>
              <span class={["pipeline-node-detail-state", @selected_style.class]}>
                <%= @selected_style.label %>
              </span>
            </div>

            <p class="pipeline-node-detail-summary">
              <%= Map.get(@selected_segment, :accessible_summary) %>
            </p>

            <div :if={@selected_metrics != []} class="pipeline-node-detail-section">
              <h4>Metrics</h4>
              <div class="pipeline-node-detail-chips">
                <span :for={metric <- @selected_metrics}><%= metric %></span>
              </div>
            </div>

            <div :if={Map.get(@selected_segment, :badges, []) != []} class="pipeline-node-detail-section">
              <h4>Badges</h4>
              <div class="pipeline-node-detail-chips">
                <span :for={badge <- @selected_segment.badges}><%= badge.label %></span>
              </div>
            </div>

            <div :if={Map.get(@selected_segment, :warnings, []) != []} class="pipeline-node-detail-section">
              <h4>Warnings</h4>
              <ul class="pipeline-node-detail-list">
                <li :for={warning <- @selected_segment.warnings}><%= warning %></li>
              </ul>
            </div>

            <div :if={@selected_rows != []} class="pipeline-node-detail-section">
              <h4>Details</h4>
              <dl class="pipeline-node-detail-grid">
                <div :for={row <- @selected_rows}>
                  <dt><%= row.key %></dt>
                  <dd><%= row.value %></dd>
                </div>
              </dl>
            </div>
          </div>

          <p :if={!@selected_segment} class="pipeline-node-detail-empty">
            Select a pipeline node to inspect its telemetry.
          </p>
        </aside>
      </div>

      <section class="sr-only" aria-label="Pipeline summary table">
        <table>
          <thead>
            <tr>
              <th>Segment</th>
              <th>State</th>
              <th>Throughput</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={row <- @summary_rows}>
              <td><%= row.segment %></td>
              <td><%= row.state %></td>
              <td><%= row.throughput %></td>
              <td><%= row.details %></td>
            </tr>
          </tbody>
        </table>
      </section>
    </section>
    """
  end

  defp graph_nodes(segments, selected_segment_id) do
    selected = selected_segment(segments, selected_segment_id)
    selected_id = if selected, do: selected.id

    columns = graph_columns(segments)

    columns
    |> Enum.zip(column_positions(length(columns)))
    |> Enum.flat_map(fn {column_segments, x} -> position_column(column_segments, x) end)
    |> Enum.map(fn {segment, x, y} ->
      state = segment_state(segment)
      style = state_style(state)

      %{
        id: segment.id,
        label: segment.label,
        x: x,
        y: y,
        state_class: style.class,
        selected: segment.id == selected_id,
        throughput: node_throughput(segment),
        accessible_summary: Map.get(segment, :accessible_summary),
        style: "left: #{format_number(x)}%; top: #{format_number(y)}%;"
      }
    end)
  end

  defp graph_columns(segments) do
    [
      segments_for(segments, ["mirror_port"]),
      segments_for(segments, ["af_packet"]),
      analysis_segments(segments),
      segments_for(segments, ["vector"]),
      segments_for(segments, ["forwarding_sinks"])
    ]
    |> Enum.reject(&(&1 == []))
  end

  defp column_positions(0), do: []
  defp column_positions(1), do: [50]

  defp column_positions(count) do
    step = 84 / (count - 1)
    Enum.map(0..(count - 1), &(8 + &1 * step))
  end

  defp position_column(segments, x) do
    segments
    |> Enum.zip(y_positions(length(segments)))
    |> Enum.map(fn {segment, y} -> {segment, x, y} end)
  end

  defp y_positions(0), do: []
  defp y_positions(1), do: [50]
  defp y_positions(2), do: [34, 66]
  defp y_positions(3), do: [24, 50, 76]

  defp y_positions(count) do
    step = 64 / (count - 1)
    Enum.map(0..(count - 1), &(18 + &1 * step))
  end

  defp graph_edges(connectors, node_map) do
    connectors
    |> Enum.filter(
      &(Map.has_key?(node_map, &1.source_id) and Map.has_key?(node_map, &1.target_id))
    )
    |> Enum.map(fn connector ->
      source = Map.fetch!(node_map, connector.source_id)
      target = Map.fetch!(node_map, connector.target_id)
      path = edge_path(source, target)
      flow_state = Map.get(connector, :flow_state, :unknown)
      speed_tier = Map.get(connector, :speed_tier, :unknown)

      %{
        id: connector.id,
        path: path,
        class: "pipeline-node-flow-state-#{flow_state} pipeline-node-flow-speed-#{speed_tier}",
        animated: flow_state in [:flowing, :degraded],
        accessible_summary: Map.get(connector, :accessible_summary)
      }
    end)
  end

  defp edge_path(source, target) do
    start_x = source.x + 5.2
    end_x = target.x - 5.2
    diff = max(end_x - start_x, 8)
    c1_x = start_x + diff * 0.45
    c2_x = end_x - diff * 0.45

    "M #{format_number(start_x)} #{format_number(source.y)} C #{format_number(c1_x)} #{format_number(source.y)}, #{format_number(c2_x)} #{format_number(target.y)}, #{format_number(end_x)} #{format_number(target.y)}"
  end

  defp segments_for(segments, ids), do: Enum.filter(segments, &(&1.id in ids))

  defp analysis_segments(segments) do
    canonical = segments_for(segments, ["zeek", "suricata", "pcap_ring"])

    dynamic =
      segments
      |> Enum.filter(&String.starts_with?(&1.id, "capture_consumer:"))
      |> Enum.sort_by(& &1.id)

    canonical ++ dynamic
  end

  defp selected_segment(segments, nil), do: default_selected_segment(segments)

  defp selected_segment(segments, selected_segment_id) do
    Enum.find(segments, &(&1.id == selected_segment_id)) || default_selected_segment(segments)
  end

  defp default_selected_segment(segments) do
    Enum.find(segments, &(&1.id == "af_packet")) ||
      List.first(segments)
  end

  defp state_style(state), do: Map.get(@state_styles, state, Map.fetch!(@state_styles, :no_data))
  defp segment_state(nil), do: :no_data
  defp segment_state(segment), do: Map.get(segment, :state, :no_data)

  defp node_throughput(segment) do
    metrics = Map.get(segment, :metrics, %{})

    Map.get(metrics, :throughput) ||
      Map.get(metrics, :aggregate_throughput) ||
      "—"
  end

  defp detail_metrics(nil), do: []

  defp detail_metrics(segment) do
    segment
    |> Map.get(:metrics, %{})
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" or value == "—" end)
    |> Enum.map(fn {key, value} -> "#{humanize(key)}: #{tooltip_value(value)}" end)
    |> Enum.sort()
  end

  defp tooltip_rows(tooltip) when is_map(tooltip) do
    tooltip
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" or value == [] end)
    |> Enum.map(fn {key, value} -> %{key: humanize(key), value: tooltip_value(value)} end)
    |> Enum.sort_by(& &1.key)
  end

  defp tooltip_rows(_tooltip), do: []

  defp tooltip_value(value) when is_map(value) do
    value
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
    |> Enum.map(fn {key, value} -> "#{humanize(key)}: #{tooltip_value(value)}" end)
    |> Enum.join(", ")
  end

  defp tooltip_value(value) when is_list(value) do
    value
    |> Enum.map(&tooltip_value/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("; ")
  end

  defp tooltip_value(value), do: to_string(value)

  defp stale_label(nil), do: "Report age is unknown."
  defp stale_label(seconds), do: "Last report was #{seconds} seconds ago."

  defp dom_id(value) do
    value
    |> to_string()
    |> String.replace(~r/[^a-zA-Z0-9_-]/, "-")
  end

  defp humanize(value) do
    value
    |> to_string()
    |> String.replace("capture_consumer:", "")
    |> String.replace("_", " ")
    |> String.replace("-", " ")
    |> String.split()
    |> Enum.map_join(" ", &String.capitalize/1)
  end

  defp format_number(value) when is_integer(value), do: Integer.to_string(value)

  defp format_number(value) when is_float(value),
    do: :erlang.float_to_binary(value, decimals: 2)
end
