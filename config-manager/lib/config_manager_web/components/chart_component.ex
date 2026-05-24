defmodule ConfigManagerWeb.ChartComponent do
  @moduledoc "Accessible metric chart and fallback table components."

  use ConfigManagerWeb, :html

  attr(:slot, :map, required: true)
  attr(:table_view?, :boolean, default: false)

  def metric_slot(%{slot: %{state: :data}} = assigns) do
    assigns =
      assigns
      |> assign(:chart_json, Jason.encode!(assigns.slot.chart))
      |> assign(:summary, summary(assigns.slot))

    ~H"""
    <section class="rounded border border-gray-200 bg-white p-4" aria-label={@summary}>
      <div class="mb-3 flex items-start justify-between gap-3">
        <div>
          <h2 class="text-base font-semibold text-gray-900"><%= @slot.label %></h2>
          <p class="text-sm text-gray-500"><%= @summary %></p>
        </div>
        <button type="button" phx-click="toggle_table" phx-value-key={@slot.key} class="rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-800">
          <%= if @table_view?, do: "View chart", else: "View as table" %>
        </button>
      </div>
      <%= if @table_view? do %>
        <.metric_table slot={@slot} />
      <% else %>
        <div
          id={"metrics-chart-#{@slot.key}"}
          phx-hook="MetricsChart"
          data-chart={@chart_json}
          class="h-72"
        >
          <canvas id={"metrics-chart-#{@slot.key}-canvas"} class="h-full w-full" aria-label={@summary}></canvas>
        </div>
      <% end %>
      <%= if @slot[:downsampled?] do %>
        <p class="mt-2 text-xs text-gray-500">Data was downsampled to keep the chart readable.</p>
      <% end %>
      <%= if threshold_note(@slot.metric_type) do %>
        <p class="mt-2 text-xs text-gray-500"><%= threshold_note(@slot.metric_type) %></p>
      <% end %>
    </section>
    """
  end

  def metric_slot(assigns) do
    ~H"""
    <section class={"rounded border p-4 #{@slot.class}"} aria-label={@slot.message}>
      <h2 class="text-base font-semibold text-gray-900"><%= @slot.label %></h2>
      <p class="mt-2 text-sm"><%= @slot.message %></p>
    </section>
    """
  end

  attr(:slot, :map, required: true)

  def metric_table(assigns) do
    ~H"""
    <div class="max-h-72 overflow-auto">
      <table class="min-w-full text-left text-sm">
        <thead class="border-b border-gray-200 text-xs uppercase text-gray-500">
          <tr>
            <th class="py-2 pr-4">Series</th>
            <th class="py-2 pr-4">Timestamp</th>
            <th class="py-2 pr-4">Value</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100">
          <%= for point <- table_points(@slot) do %>
            <tr>
              <td class="py-2 pr-4 text-gray-700"><%= point.series %></td>
              <td class="py-2 pr-4 text-gray-700"><%= point.timestamp %></td>
              <td class="py-2 pr-4 font-medium text-gray-900"><%= point.value %></td>
            </tr>
          <% end %>
        </tbody>
      </table>
    </div>
    """
  end

  defp table_points(slot) do
    slot.chart.series
    |> Enum.flat_map(fn series ->
      Enum.map(series.points, fn point ->
        %{
          series: series.label,
          timestamp: point.label,
          value: format_value(point.value, slot.unit)
        }
      end)
    end)
    |> Enum.sort_by(& &1.timestamp, :desc)
  end

  defp summary(slot) do
    values =
      slot.chart.series
      |> Enum.flat_map(&Enum.map(&1.points, fn point -> point.value end))

    case values do
      [] ->
        "#{slot.label} chart, #{slot.range}, no data"

      values ->
        "#{slot.label} chart, #{slot.range}, range #{format_value(Enum.min(values), slot.unit)} to #{format_value(Enum.max(values), slot.unit)}"
    end
  end

  defp threshold_note("drop_percent"), do: "Warning threshold: above 1%. Critical threshold: above 5%."
  defp threshold_note("cpu_percent"), do: "Warning threshold: above 80%. Critical threshold: above 95%."
  defp threshold_note("pcap_disk_used_percent"), do: "Warning threshold: above 85%. Critical threshold: above 95%."
  defp threshold_note("clock_offset_ms"), do: "Warning threshold: outside +/-50 ms. Critical threshold: outside +/-100 ms."
  defp threshold_note(_metric_type), do: nil

  defp format_value(value, "bytes") when is_number(value), do: format_bytes(value)
  defp format_value(value, "%") when is_number(value), do: "#{Float.round(value / 1, 2)}%"
  defp format_value(value, unit) when is_number(value), do: "#{Float.round(value / 1, 2)} #{unit}"
  defp format_value(value, _unit), do: to_string(value)

  defp format_bytes(value) when value >= 1_073_741_824, do: "#{Float.round(value / 1_073_741_824, 2)} GB"
  defp format_bytes(value) when value >= 1_048_576, do: "#{Float.round(value / 1_048_576, 2)} MB"
  defp format_bytes(value) when value >= 1024, do: "#{Float.round(value / 1024, 2)} KB"
  defp format_bytes(value), do: "#{round(value)} B"
end
