defmodule ConfigManagerWeb.MetricsLive.PoolMetricsLive do
  @moduledoc "Historical aggregate metrics for a sensor pool."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers

  alias ConfigManager.{Metrics, Pools}
  alias ConfigManagerWeb.ChartComponent

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        members = Pools.list_pool_sensors(pool.id)

        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}")
          Enum.each(members, &Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_metrics:#{&1.id}"))
        end

        {:ok,
         socket
         |> assign(:not_found, false)
         |> assign(:pool, pool)
         |> assign(:members, members)
         |> assign(:member_ids, MapSet.new(Enum.map(members, & &1.id)))
         |> assign(:table_views, %{})
         |> assign(:expanded, %{})
         |> assign(:page_title, "#{pool.name} Metrics")}
    end
  end

  @impl true
  def handle_params(_params, _uri, %{assigns: %{not_found: true}} = socket), do: {:noreply, socket}

  def handle_params(params, _uri, socket) do
    range = Metrics.range_or_default(params["range"])
    {:noreply, load_metrics(socket, range)}
  end

  @impl true
  def handle_event("select_range", %{"range" => range}, socket) do
    range = Metrics.range_or_default(range)
    {:noreply, push_patch(socket, to: "/pools/#{socket.assigns.pool.id}/metrics?range=#{range}")}
  end

  def handle_event("toggle_table", %{"key" => key}, socket) do
    {:noreply, assign(socket, :table_views, Map.update(socket.assigns.table_views, key, true, &(!&1)))}
  end

  def handle_event("expand_chart", %{"key" => key}, socket) do
    {:noreply, assign(socket, :expanded, Map.update(socket.assigns.expanded, key, true, &(!&1)))}
  end

  @impl true
  def handle_info({:metrics_updated, sensor_pod_id}, socket) do
    if MapSet.member?(socket.assigns.member_ids, sensor_pod_id) do
      {:noreply, load_metrics(socket, socket.assigns.range)}
    else
      {:noreply, socket}
    end
  end

  def handle_info({event, pool_id, _sensor_ids}, %{assigns: %{pool: %{id: pool_id}}} = socket)
      when event in [:sensors_assigned, :sensors_removed] do
    members = Pools.list_pool_sensors(pool_id)
    {:noreply, socket |> assign(:members, members) |> assign(:member_ids, MapSet.new(Enum.map(members, & &1.id))) |> load_metrics(socket.assigns.range)}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-4xl px-6 py-10">
      <h1 class="text-2xl font-bold text-gray-900">Pool Not Found</h1>
      <p class="mt-2 text-gray-600">The requested pool does not exist.</p>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <a href={"/pools/#{@pool.id}"} class="text-sm text-blue-600 hover:underline">Back to pool</a>
      <div class="mt-2 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold text-gray-900"><%= @pool.name %> Metrics</h1>
          <p class="text-sm text-gray-500">Historical health metrics for pool members.</p>
        </div>
        <ConfigManagerWeb.MetricsLive.SensorMetricsLive.range_selector range={@range} />
      </div>

      <.pool_nav pool={@pool} />

      <%= if @members == [] do %>
        <section class="mt-6 rounded border border-gray-200 bg-gray-50 p-4 text-sm text-gray-700">
          No sensors assigned to this pool.
        </section>
      <% else %>
        <section class="mt-6 grid gap-4 lg:grid-cols-2">
          <%= for slot <- @slots do %>
            <div>
              <%= if @large_pool? and slot.state == :data do %>
                <button type="button" phx-click="expand_chart" phx-value-key={slot.key} class="mb-2 rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-800">
                  <%= if Map.get(@expanded, slot.key, false), do: "Show summary", else: "Show individual sensors" %>
                </button>
              <% end %>
              <ChartComponent.metric_slot slot={display_slot(slot, @large_pool?, Map.get(@expanded, slot.key, false))} table_view?={Map.get(@table_views, slot.key, false)} />
            </div>
          <% end %>
        </section>
      <% end %>
    </main>
    """
  end

  defp load_metrics(socket, range) do
    slots = Enum.map(Metrics.chart_order(), &metric_slot(&1, socket.assigns.pool.id, range, socket.assigns.members))

    socket
    |> assign(:range, range)
    |> assign(:slots, slots)
    |> assign(:large_pool?, length(socket.assigns.members) > 10)
  end

  defp metric_slot(metric_type, pool_id, range, members) do
    label = Metrics.metric_label(metric_type)

    cond do
      metric_type in Metrics.future_types() ->
        %{
          key: metric_type,
          metric_type: metric_type,
          label: label,
          state: :unavailable,
          class: "border-blue-200 bg-blue-50 text-blue-900",
          message: "Data source not yet available - requires HealthReport protobuf extension for #{label}."
        }

      members == [] ->
        %{
          key: metric_type,
          metric_type: metric_type,
          label: label,
          state: :no_data,
          class: "border-gray-200 bg-gray-50 text-gray-700",
          message: "No sensors assigned to this pool."
        }

      true ->
        case Metrics.list_snapshots_for_pool(pool_id, metric_type, range) do
          {:ok, %{snapshots: snapshots}} when map_size(snapshots) == 0 ->
            %{
              key: metric_type,
              metric_type: metric_type,
              label: label,
              state: :no_data,
              class: "border-gray-200 bg-gray-50 text-gray-700",
              message: "No data recorded for #{label} in the selected time range."
            }

          {:ok, %{snapshots: snapshots, members: members}} ->
            data_slot(metric_type, label, range, snapshots, members)

          {:error, :invalid_range} ->
            metric_slot(metric_type, pool_id, Metrics.default_range(), members)
        end
    end
  end

  defp data_slot(metric_type, label, range, snapshots, members) do
    members_by_id = Map.new(members, &{&1.id, &1})

    series =
      Enum.map(snapshots, fn {{sensor_id, series_key}, values} ->
        sensor_name = Map.get(members_by_id, sensor_id, %{name: sensor_id}).name
        label = pool_series_label(sensor_name, series_key, values)
        %{id: "#{sensor_id}:#{series_key}", label: label, points: Enum.map(values, &point/1)}
      end)

    %{
      key: metric_type,
      metric_type: metric_type,
      label: label,
      state: :data,
      range: range,
      unit: Metrics.metric_unit(metric_type),
      downsampled?: series |> Enum.flat_map(& &1.points) |> Enum.any?(&Map.get(&1, :downsampled?, false)),
      chart: %{metric_type: metric_type, label: label, unit: Metrics.metric_unit(metric_type), series: series},
      summary_chart: summary_chart(metric_type, label, series)
    }
  end

  defp display_slot(%{state: :data} = slot, true, false), do: %{slot | chart: slot.summary_chart}
  defp display_slot(slot, _large_pool?, _expanded?), do: slot

  defp summary_chart(metric_type, label, series) do
    all_points =
      series
      |> Enum.flat_map(fn s -> Enum.map(s.points, &Map.put(&1, :series, s.label)) end)
      |> Enum.group_by(& &1.x)

    summary_series =
      for {summary_label, fun} <- [{"min", &Enum.min/1}, {"avg", &avg/1}, {"max", &Enum.max/1}] do
        %{
          id: summary_label,
          label: summary_label,
          points:
            all_points
            |> Enum.map(fn {timestamp, points} ->
              values = Enum.map(points, & &1.value)
              %{x: timestamp, label: List.first(points).label, value: fun.(values)}
            end)
            |> Enum.sort_by(& &1.x)
        }
      end

    %{metric_type: metric_type, label: label, unit: Metrics.metric_unit(metric_type), series: summary_series}
  end

  defp pool_series_label(sensor_name, "default", _values), do: sensor_name

  defp pool_series_label(sensor_name, series_key, [snapshot | _values]) do
    container = Metrics.decode_metadata(snapshot)["container_name"] || series_key
    "#{sensor_name} / #{container}"
  end

  defp point(snapshot) do
    metadata = Metrics.decode_metadata(snapshot)

    %{
      x: DateTime.to_iso8601(snapshot.recorded_at),
      label: Calendar.strftime(snapshot.recorded_at, "%Y-%m-%d %H:%M:%S UTC"),
      value: snapshot.value,
      downsampled?: metadata["downsampled"] == true
    }
  end

  defp avg(values), do: Enum.sum(values) / length(values)
end
