defmodule ConfigManagerWeb.MetricsLive.SensorMetricsLive do
  @moduledoc "Historical metrics for a single sensor."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.{Metrics, Repo, SensorPod}
  alias ConfigManagerWeb.ChartComponent

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Repo.get(SensorPod, id) do
      %SensorPod{} = pod ->
        if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_metrics:#{pod.id}")

        {:ok,
         socket
         |> assign(:not_found, false)
         |> assign(:pod, pod)
         |> assign(:table_views, %{})
         |> assign(:page_title, "#{pod.name} Metrics")}

      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Sensor Not Found")}
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
    {:noreply, push_patch(socket, to: "/sensors/#{socket.assigns.pod.id}/metrics?range=#{range}")}
  end

  def handle_event("toggle_table", %{"key" => key}, socket) do
    table_views = Map.update(socket.assigns.table_views, key, true, &(!&1))
    {:noreply, assign(socket, :table_views, table_views)}
  end

  @impl true
  def handle_info({:metrics_updated, sensor_pod_id}, %{assigns: %{pod: %{id: sensor_pod_id}}} = socket) do
    {:noreply, load_metrics(socket, socket.assigns.range)}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-4xl px-6 py-10">
      <h1 class="text-2xl font-bold text-gray-900">Sensor Not Found</h1>
      <p class="mt-2 text-gray-600">The requested sensor does not exist.</p>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <a href={"/sensors/#{@pod.id}"} class="text-sm text-blue-600 hover:underline">Back to sensor</a>
      <div class="mt-2 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold text-gray-900"><%= @pod.name %> Metrics</h1>
          <p class="text-sm text-gray-500">Historical health metrics for the selected sensor.</p>
        </div>
        <.range_selector range={@range} />
      </div>

      <%= if @pod.status in ["pending", "revoked"] do %>
        <section class="mt-4 rounded border border-yellow-200 bg-yellow-50 p-4 text-sm text-yellow-900">
          Sensor status is <strong><%= @pod.status %></strong>. Historical snapshots are shown when available.
        </section>
      <% end %>

      <%= if @offline? do %>
        <section class="mt-4 rounded border border-gray-200 bg-gray-50 p-4 text-sm text-gray-700">
          Sensor was offline during the selected time range.
        </section>
      <% end %>

      <section class="mt-6 grid gap-4 lg:grid-cols-2">
        <%= for slot <- @slots do %>
          <ChartComponent.metric_slot slot={slot} table_view?={Map.get(@table_views, slot.key, false)} />
        <% end %>
      </section>
    </main>
    """
  end

  attr(:range, :string, required: true)

  def range_selector(assigns) do
    ~H"""
    <form phx-change="select_range" class="flex items-center gap-2 text-sm" aria-label="Time range">
      <label for="metrics-range" class="font-medium text-gray-700">Range</label>
      <select id="metrics-range" name="range" class="rounded border border-gray-300 px-3 py-2">
        <%= for range <- Metrics.valid_time_ranges() do %>
          <option value={range} selected={@range == range}><%= range %></option>
        <% end %>
      </select>
    </form>
    """
  end

  defp load_metrics(socket, range) do
    slots = metric_slots(socket.assigns.pod, range)
    offline? = Enum.all?(slots, &(&1.state != :data or &1.metric_type in Metrics.future_types()))

    socket
    |> assign(:range, range)
    |> assign(:slots, slots)
    |> assign(:offline?, offline?)
  end

  defp metric_slots(%SensorPod{} = pod, range) do
    Enum.map(Metrics.chart_order(), fn metric_type ->
      metric_slot(metric_type, pod.id, range)
    end)
  end

  defp metric_slot(metric_type, sensor_pod_id, range) do
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

      true ->
        case Metrics.list_snapshots(sensor_pod_id, metric_type, range) do
          {:ok, []} ->
            %{
              key: metric_type,
              metric_type: metric_type,
              label: label,
              state: :no_data,
              class: "border-gray-200 bg-gray-50 text-gray-700",
              message: "No data recorded for #{label} in the selected time range."
            }

          {:ok, snapshots} ->
            data_slot(metric_type, label, range, snapshots)

          {:error, :invalid_range} ->
            metric_slot(metric_type, sensor_pod_id, Metrics.default_range())
        end
    end
  end

  defp data_slot(metric_type, label, range, snapshots) do
    series =
      snapshots
      |> Enum.group_by(& &1.series_key)
      |> Enum.map(fn {series_key, values} ->
        %{
          id: series_key,
          label: series_label(series_key, values),
          points: Enum.map(values, &point/1)
        }
      end)

    %{
      key: metric_type,
      metric_type: metric_type,
      label: label,
      state: :data,
      range: range,
      unit: Metrics.metric_unit(metric_type),
      downsampled?: Enum.any?(snapshots, &(Metrics.decode_metadata(&1)["downsampled"] == true)),
      chart: %{metric_type: metric_type, label: label, unit: Metrics.metric_unit(metric_type), series: series}
    }
  end

  defp series_label("default", _values), do: "default"

  defp series_label(series_key, [snapshot | _values]) do
    Metrics.decode_metadata(snapshot)["container_name"] || series_key
  end

  defp point(snapshot) do
    %{
      x: DateTime.to_iso8601(snapshot.recorded_at),
      label: Calendar.strftime(snapshot.recorded_at, "%Y-%m-%d %H:%M:%S UTC"),
      value: snapshot.value
    }
  end
end
