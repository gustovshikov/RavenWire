defmodule ConfigManagerWeb.PipelineComponent do
  @moduledoc "Reusable function components for the live data-flow pipeline visualization."

  use Phoenix.Component

  @state_styles %{
    healthy: %{
      class: "pipeline-state-healthy",
      icon: "OK",
      label: "Healthy"
    },
    degraded: %{
      class: "pipeline-state-degraded",
      icon: "!",
      label: "Degraded"
    },
    failed: %{
      class: "pipeline-state-failed",
      icon: "X",
      label: "Failed"
    },
    disabled: %{
      class: "pipeline-state-disabled",
      icon: "/",
      label: "Disabled"
    },
    pending_reload: %{
      class: "pipeline-state-pending",
      icon: "R",
      label: "Pending Reload"
    },
    no_data: %{
      class: "pipeline-state-no-data",
      icon: "?",
      label: "No Data"
    }
  }

  attr(:pipeline_state, :map, required: true)
  attr(:mode, :atom, values: [:sensor, :pool], required: true)
  attr(:stale, :boolean, default: nil)
  attr(:stale_age_seconds, :integer, default: nil)
  attr(:sensor_status, :any, default: nil)
  attr(:pool_member_links, :list, default: [])

  def pipeline_visualization(assigns) do
    stale =
      if is_nil(assigns.stale),
        do: Map.get(assigns.pipeline_state, :stale, false),
        else: assigns.stale

    stale_age_seconds =
      if is_nil(assigns.stale_age_seconds),
        do: Map.get(assigns.pipeline_state, :stale_age_seconds),
        else: assigns.stale_age_seconds

    assigns =
      assigns
      |> assign(:segments, Map.get(assigns.pipeline_state, :segments, []))
      |> assign(:connectors, Map.get(assigns.pipeline_state, :connectors, []))
      |> assign(:stage_groups, stage_groups(Map.get(assigns.pipeline_state, :segments, [])))
      |> assign(:summary_rows, Map.get(assigns.pipeline_state, :summary_rows, []))
      |> assign(:status_banners, Map.get(assigns.pipeline_state, :status_banners, []))
      |> assign(:stale, stale)
      |> assign(:stale_age_seconds, stale_age_seconds)

    ~H"""
    <section class="pipeline-card" aria-labelledby="pipeline-title">
      <div class="pipeline-heading">
        <div>
          <h2 id="pipeline-title" class="text-xl font-semibold text-gray-900">Live Data Flow</h2>
          <p class="text-sm text-gray-500">
            <%= if @mode == :pool do %>
              Aggregate pipeline health for this pool.
            <% else %>
              Current sensor pipeline state from the latest HealthReport.
            <% end %>
          </p>
        </div>
        <div :if={@mode == :pool} class="pipeline-member-count">
          <span><%= Map.get(@pipeline_state, :reporting_members, 0) %></span>
          <span class="text-gray-500">/ <%= Map.get(@pipeline_state, :total_members, 0) %> reporting</span>
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

      <div class="pipeline-graph" role="group" aria-label="Pipeline topology">
        <div :for={stage <- @stage_groups} class="pipeline-stage">
          <div class="pipeline-stage-label"><%= stage.label %></div>
          <.segment_node
            :for={segment <- stage.segments}
            segment={segment}
            mode={@mode}
            stale={@stale}
          />
        </div>
      </div>

      <div class="pipeline-connectors" aria-label="Pipeline connectors">
        <.segment_connector :for={connector <- @connectors} connector={connector} />
      </div>

      <.summary_table rows={@summary_rows} mode={@mode} />

      <div :if={@pool_member_links != []} class="pipeline-member-links">
        <h3 class="text-sm font-semibold text-gray-900">Member Sensor Pipelines</h3>
        <div class="mt-2 flex flex-wrap gap-2">
          <a :for={member <- @pool_member_links} href={member.href} class="pipeline-member-link">
            <%= member.label %>
          </a>
        </div>
      </div>
    </section>
    """
  end

  attr(:segment, :map, required: true)
  attr(:mode, :atom, values: [:sensor, :pool], required: true)
  attr(:stale, :boolean, default: false)

  def segment_node(assigns) do
    state = segment_state(assigns.segment, assigns.mode)
    style = Map.fetch!(@state_styles, state)

    assigns =
      assigns
      |> assign(:state, state)
      |> assign(:state_style, style)

    ~H"""
    <article
      id={"pipeline-segment-#{dom_id(@segment.id)}"}
      class={[
        "pipeline-segment",
        @state_style.class,
        @stale && "pipeline-segment-stale"
      ]}
      tabindex="0"
      aria-label={Map.get(@segment, :accessible_summary)}
    >
      <div class="pipeline-segment-title">
        <span class="pipeline-state-icon" aria-hidden="true"><%= @state_style.icon %></span>
        <div>
          <h3><%= @segment.label %></h3>
          <p><%= @state_style.label %></p>
        </div>
      </div>

      <div :if={@mode == :sensor} class="pipeline-metrics">
        <span :for={metric <- visible_metrics(@segment)}><%= metric %></span>
      </div>

      <div :if={@mode == :pool} class="pipeline-counts">
        <span :for={count <- visible_counts(@segment)}><%= count %></span>
      </div>

      <div :if={Map.get(@segment, :badges, []) != []} class="pipeline-badges">
        <span :for={badge <- @segment.badges} class="pipeline-badge"><%= badge.label %></span>
      </div>

      <div :if={Map.get(@segment, :warnings, []) != []} class="pipeline-warnings">
        <span :for={warning <- @segment.warnings}><%= warning %></span>
      </div>

      <.segment_tooltip segment={@segment} />
    </article>
    """
  end

  attr(:connector, :map, required: true)

  def segment_connector(assigns) do
    assigns =
      assigns
      |> assign(:flow_class, flow_class(assigns.connector))
      |> assign(:animated?, Map.get(assigns.connector, :flow_state) in [:flowing, :degraded])

    ~H"""
    <div
      id={"pipeline-connector-#{dom_id(@connector.id)}"}
      class={["pipeline-connector", @flow_class]}
      tabindex="0"
      aria-label={@connector.accessible_summary}
    >
      <span class="pipeline-connector-label"><%= connector_endpoint_label(@connector.source_id) %></span>
      <svg viewBox="0 0 160 24" role="img" aria-hidden="true" focusable="false">
        <defs>
          <marker id={"arrow-#{dom_id(@connector.id)}"} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L7,3 z" />
          </marker>
        </defs>
        <path class="pipeline-connector-base" d="M4 12 H152" marker-end={"url(#arrow-#{dom_id(@connector.id)})"} />
        <path :if={@animated?} class="pipeline-connector-flow" d="M4 12 H152" />
      </svg>
      <span class="pipeline-connector-label"><%= connector_endpoint_label(@connector.target_id) %></span>
      <span class="pipeline-connector-rate"><%= @connector.throughput_label %></span>
      <span :if={@connector.secondary_label} class="pipeline-connector-secondary">
        <%= @connector.secondary_label %>
      </span>
    </div>
    """
  end

  attr(:segment, :map, required: true)

  def segment_tooltip(assigns) do
    assigns = assign(assigns, :rows, tooltip_rows(Map.get(assigns.segment, :tooltip, %{})))

    ~H"""
    <details
      id={"pipeline-tooltip-#{dom_id(@segment.id)}"}
      class="pipeline-tooltip"
      phx-hook="PipelineTooltip"
      aria-label={"Details for #{@segment.label}"}
    >
      <summary>Details</summary>
      <dl>
        <div :for={row <- @rows}>
          <dt><%= row.key %></dt>
          <dd><%= row.value %></dd>
        </div>
      </dl>
    </details>
    """
  end

  attr(:rows, :list, required: true)
  attr(:mode, :atom, values: [:sensor, :pool], required: true)

  def summary_table(assigns) do
    ~H"""
    <section class="pipeline-summary" aria-label="Pipeline summary table">
      <h3 class="text-sm font-semibold text-gray-900">Pipeline Summary</h3>
      <div class="mt-2 overflow-x-auto">
        <table>
          <thead>
            <tr :if={@mode == :sensor}>
              <th>Segment</th>
              <th>State</th>
              <th>Throughput</th>
              <th>Details</th>
            </tr>
            <tr :if={@mode == :pool}>
              <th>Segment</th>
              <th>Overall</th>
              <th>Healthy</th>
              <th>Degraded</th>
              <th>Failed</th>
              <th>Pending</th>
              <th>Disabled</th>
              <th>No Data</th>
            </tr>
          </thead>
          <tbody>
            <tr :if={@mode == :sensor} :for={row <- @rows}>
              <td><%= row.segment %></td>
              <td><%= row.state %></td>
              <td><%= row.throughput %></td>
              <td><%= row.details %></td>
            </tr>
            <tr :if={@mode == :pool} :for={row <- @rows}>
              <td><%= row.segment %></td>
              <td><%= row.overall_state %></td>
              <td><%= row.healthy %></td>
              <td><%= row.degraded %></td>
              <td><%= row.failed %></td>
              <td><%= row.pending_reload %></td>
              <td><%= row.disabled %></td>
              <td><%= row.no_data %></td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
    """
  end

  defp stage_groups(segments) do
    [
      %{label: "Ingress", segments: segments_for(segments, ["mirror_port"])},
      %{label: "Capture", segments: segments_for(segments, ["af_packet"])},
      %{label: "Analysis", segments: analysis_segments(segments)},
      %{label: "Transport", segments: segments_for(segments, ["vector"])},
      %{label: "Egress", segments: segments_for(segments, ["forwarding_sinks"])}
    ]
    |> Enum.reject(&(&1.segments == []))
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

  defp segment_state(segment, :pool), do: Map.get(segment, :overall_state, :no_data)
  defp segment_state(segment, _mode), do: Map.get(segment, :state, :no_data)

  defp visible_metrics(segment) do
    metrics = Map.get(segment, :metrics, %{})

    [
      metric("ingest", Map.get(metrics, :ingest)),
      metric(
        "throughput",
        Map.get(metrics, :throughput) || Map.get(metrics, :aggregate_throughput)
      ),
      metric("consumers", Map.get(metrics, :consumer_count)),
      metric(
        "drops",
        percent(Map.get(metrics, :drop_percent) || Map.get(metrics, :max_drop_percent))
      ),
      metric("storage", Map.get(metrics, :storage_used_label)),
      metric("sinks", sink_count(metrics)),
      metric("container", Map.get(metrics, :container_state))
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp visible_counts(segment) do
    counts = Map.get(segment, :state_counts, %{})

    [
      count("healthy", counts[:healthy]),
      count("degraded", counts[:degraded]),
      count("failed", counts[:failed]),
      count("pending", counts[:pending_reload]),
      count("disabled", counts[:disabled]),
      count("no data", counts[:no_data])
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp metric(_label, nil), do: nil
  defp metric(_label, ""), do: nil
  defp metric(_label, "—"), do: nil
  defp metric(label, value), do: "#{label}: #{value}"

  defp count(_label, nil), do: nil
  defp count(_label, 0), do: nil
  defp count(label, value), do: "#{value} #{label}"

  defp percent(nil), do: nil

  defp percent(value) when is_number(value),
    do: :erlang.float_to_binary(value / 1, decimals: 1) <> "%"

  defp percent(_value), do: nil

  defp sink_count(%{sink_count: sink_count, enabled_count: enabled_count}) when sink_count > 0,
    do: "#{enabled_count}/#{sink_count} enabled"

  defp sink_count(_metrics), do: nil

  defp tooltip_rows(tooltip) when is_map(tooltip) do
    tooltip
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" or value == [] end)
    |> Enum.map(fn {key, value} ->
      %{key: humanize(key), value: tooltip_value(value)}
    end)
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

  defp flow_class(connector) do
    flow_state = Map.get(connector, :flow_state, :unknown)
    speed_tier = Map.get(connector, :speed_tier, :unknown)
    "flow-state-#{flow_state} flow-speed-#{speed_tier}"
  end

  defp connector_endpoint_label("capture_consumer:" <> name), do: humanize(name)
  defp connector_endpoint_label(id), do: humanize(id)

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
end
