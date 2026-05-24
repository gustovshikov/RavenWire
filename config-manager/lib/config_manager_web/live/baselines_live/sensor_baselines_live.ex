defmodule ConfigManagerWeb.BaselinesLive.SensorBaselinesLive do
  @moduledoc "Health baselines for a single sensor."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.{Baselines, Metrics, Repo, SensorPod}

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Repo.get(SensorPod, id) do
      %SensorPod{} = pod ->
        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "baselines:sensor:#{pod.id}")
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_metrics:#{pod.id}")
        end

        {:ok,
         socket
         |> assign(:not_found, false)
         |> assign(:pod, pod)
         |> assign(:page_title, "#{pod.name} Baselines")
         |> load_baselines()}

      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Sensor Not Found")}
    end
  end

  @impl true
  def handle_info({event, _sensor_pod_id}, socket)
      when event in [:baselines_updated, :forecasts_updated, :metrics_updated] do
    {:noreply, load_baselines(socket)}
  end

  def handle_info({:anomaly_status, _sensor_pod_id, _status}, socket) do
    {:noreply, load_baselines(socket)}
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
          <h1 class="text-2xl font-bold text-gray-900"><%= @pod.name %> Baselines</h1>
          <p class="text-sm text-gray-500">Statistical health baselines and capacity forecasts for this sensor.</p>
        </div>
      </div>

      <section class="mt-6 grid gap-4 lg:grid-cols-2">
        <%= for card <- @cards do %>
          <article class={"rounded border bg-white p-4 #{card_class(card.status)}"}>
            <div class="flex items-start justify-between gap-3">
              <div>
                <h2 class="text-base font-semibold text-gray-900"><%= card.label %></h2>
                <p class="mt-1 text-sm text-gray-500"><%= card.summary %></p>
              </div>
              <span class={"rounded px-2 py-1 text-xs font-medium #{status_badge_class(card.status)}"}><%= card.status_label %></span>
            </div>

            <%= if card.baseline do %>
              <dl class="mt-4 grid grid-cols-2 gap-3 text-sm">
                <.metric label="Mean" value={format_value(card.baseline.mean, card.unit)} />
                <.metric label="Stddev" value={format_value(card.baseline.stddev, card.unit)} />
                <.metric label="P5 / P95" value={"#{format_value(card.baseline.p5, card.unit)} - #{format_value(card.baseline.p95, card.unit)}"} />
                <.metric label="Current" value={format_optional_value(card.current_value, card.unit)} />
                <.metric label="Samples" value={card.baseline.sample_count} />
                <.metric label="Anomaly Score" value={format_score(card.anomaly_score)} />
              </dl>
              <%= if card.forecast do %>
                <p class="mt-3 rounded bg-yellow-50 px-3 py-2 text-sm text-yellow-900">
                  Forecast projects <%= format_value(card.forecast.projected_value, card.unit) %> against threshold <%= format_value(card.forecast.threshold, card.unit) %>.
                </p>
              <% else %>
                <p class="mt-3 text-xs text-gray-500">Insufficient data for forecast.</p>
              <% end %>
            <% else %>
              <p class="mt-4 rounded bg-gray-50 px-3 py-2 text-sm text-gray-700">Baseline not available. Insufficient data for baseline.</p>
            <% end %>
          </article>
        <% end %>
      </section>
    </main>
    """
  end

  attr(:label, :string, required: true)
  attr(:value, :any, required: true)

  def metric(assigns) do
    ~H"""
    <div>
      <dt class="text-xs font-medium uppercase text-gray-500"><%= @label %></dt>
      <dd class="mt-1 text-gray-900"><%= @value %></dd>
    </div>
    """
  end

  defp load_baselines(socket) do
    baselines =
      socket.assigns.pod.id
      |> Baselines.list_baselines_for_sensor()
      |> Map.new(&{{&1.metric_type, &1.series_key}, &1})

    cards =
      Metrics.protobuf_available_types()
      |> Enum.map(&card_for(socket.assigns.pod.id, &1, baselines))

    assign(socket, :cards, cards)
  end

  defp card_for(sensor_pod_id, metric_type, baselines) do
    unit = Metrics.metric_unit(metric_type)
    baseline = Map.get(baselines, {metric_type, "default"})
    current_value = Baselines.latest_value(sensor_pod_id, metric_type)
    forecast = maybe_forecast(sensor_pod_id, metric_type)
    {status, anomaly_score} = status_for(current_value, baseline)

    %{
      metric_type: metric_type,
      label: Metrics.metric_label(metric_type),
      unit: unit,
      baseline: baseline,
      current_value: current_value,
      anomaly_score: anomaly_score,
      forecast: forecast,
      status: status,
      status_label: status_label(status),
      summary: summary(status, baseline)
    }
  end

  defp status_for(nil, _baseline), do: {:unknown, nil}
  defp status_for(_current_value, nil), do: {:missing, nil}

  defp status_for(current_value, baseline) do
    case Baselines.evaluate_anomaly(current_value, baseline) do
      {:anomaly, score, _details} -> {:anomaly, score}
      :normal -> {:normal, 0.0}
    end
  end

  defp maybe_forecast(sensor_pod_id, metric_type) do
    case Baselines.compute_forecast(sensor_pod_id, metric_type) do
      {:ok, forecast} -> forecast
      {:error, _reason} -> nil
    end
  end

  defp summary(:missing, _baseline), do: "Insufficient data for baseline."
  defp summary(:unknown, _baseline), do: "No current metric value is available."
  defp summary(:anomaly, _baseline), do: "Current value deviates from the learned baseline."
  defp summary(:normal, _baseline), do: "Current value is within the learned baseline."

  defp status_label(:missing), do: "No baseline"
  defp status_label(:unknown), do: "No current data"
  defp status_label(:anomaly), do: "Anomaly"
  defp status_label(:normal), do: "Normal"

  defp card_class(:anomaly), do: "border-red-300"
  defp card_class(:normal), do: "border-green-200"
  defp card_class(_status), do: "border-gray-200"

  defp status_badge_class(:anomaly), do: "bg-red-100 text-red-800"
  defp status_badge_class(:normal), do: "bg-green-100 text-green-800"
  defp status_badge_class(_status), do: "bg-gray-100 text-gray-800"

  defp format_optional_value(nil, _unit), do: "-"
  defp format_optional_value(value, unit), do: format_value(value, unit)

  defp format_value(value, "bytes") when is_number(value), do: format_bytes(value)
  defp format_value(value, "%") when is_number(value), do: "#{Float.round(value / 1, 2)}%"
  defp format_value(value, unit) when is_number(value), do: "#{Float.round(value / 1, 2)} #{unit}"
  defp format_value(value, _unit), do: to_string(value)

  defp format_score(nil), do: "-"
  defp format_score(score), do: Float.round(score / 1, 2)

  defp format_bytes(value) when value >= 1_073_741_824,
    do: "#{Float.round(value / 1_073_741_824, 2)} GB"

  defp format_bytes(value) when value >= 1_048_576, do: "#{Float.round(value / 1_048_576, 2)} MB"
  defp format_bytes(value) when value >= 1024, do: "#{Float.round(value / 1024, 2)} KB"
  defp format_bytes(value), do: "#{round(value)} B"
end
