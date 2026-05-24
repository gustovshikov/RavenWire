defmodule ConfigManagerWeb.BaselinesLive.PoolBaselinesLive do
  @moduledoc "Pool-level health baselines and outlier comparison."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers

  alias ConfigManager.{Baselines, Metrics, Pools}

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        if connected?(socket),
          do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "baselines:pool:#{pool.id}")

        {:ok,
         socket
         |> assign(:not_found, false)
         |> assign(:pool, pool)
         |> assign(:page_title, "#{pool.name} Baselines")
         |> load_baselines()}
    end
  end

  @impl true
  def handle_info({:baselines_updated, _pool_id}, socket) do
    {:noreply, load_baselines(socket)}
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
          <h1 class="text-2xl font-bold text-gray-900"><%= @pool.name %> Baselines</h1>
          <p class="text-sm text-gray-500">Pool-level baselines and sensor outlier comparison.</p>
        </div>
      </div>

      <.pool_nav pool={@pool} />

      <%= if @members == [] do %>
        <section class="mt-6 rounded border border-gray-200 bg-gray-50 p-4 text-sm text-gray-700">
          No sensors assigned to this pool.
        </section>
      <% else %>
        <section class="mt-6 grid gap-4">
          <%= for card <- @cards do %>
            <article class="rounded border border-gray-200 bg-white p-4">
              <div class="flex items-start justify-between gap-3">
                <div>
                  <h2 class="text-base font-semibold text-gray-900"><%= card.label %></h2>
                  <p class="mt-1 text-sm text-gray-500"><%= card.summary %></p>
                </div>
              </div>

              <%= if card.baseline do %>
                <dl class="mt-4 grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                  <.field label="Pool Mean" value={format_value(card.baseline.mean, card.unit)} />
                  <.field label="Stddev" value={format_value(card.baseline.stddev, card.unit)} />
                  <.field label="P5 / P95" value={"#{format_value(card.baseline.p5, card.unit)} - #{format_value(card.baseline.p95, card.unit)}"} />
                  <.field label="Samples" value={card.baseline.sample_count} />
                </dl>

                <div class="mt-4 overflow-x-auto">
                  <table class="min-w-full text-left text-sm">
                    <thead class="border-b border-gray-200 text-xs uppercase text-gray-500">
                      <tr>
                        <th class="px-3 py-2">Sensor</th>
                        <th class="px-3 py-2">Current</th>
                        <th class="px-3 py-2">Pool Mean</th>
                        <th class="px-3 py-2">Deviation</th>
                        <th class="px-3 py-2">Status</th>
                      </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100">
                      <%= for row <- card.rows do %>
                        <tr class={if row.outlier?, do: "bg-red-50", else: ""}>
                          <td class="px-3 py-2 font-medium text-gray-900"><%= row.sensor_name %></td>
                          <td class="px-3 py-2"><%= format_optional_value(row.current_value, card.unit) %></td>
                          <td class="px-3 py-2"><%= format_value(card.baseline.mean, card.unit) %></td>
                          <td class="px-3 py-2"><%= format_optional_value(row.deviation, card.unit) %></td>
                          <td class="px-3 py-2"><%= if row.outlier?, do: "Outlier", else: "Normal" %></td>
                        </tr>
                      <% end %>
                    </tbody>
                  </table>
                </div>
              <% else %>
                <p class="mt-4 rounded bg-gray-50 px-3 py-2 text-sm text-gray-700">Insufficient sensors for pool baseline.</p>
              <% end %>
            </article>
          <% end %>
        </section>
      <% end %>
    </main>
    """
  end

  defp load_baselines(socket) do
    members = Pools.list_pool_sensors(socket.assigns.pool.id)

    baselines =
      socket.assigns.pool.id
      |> Baselines.list_baselines_for_pool()
      |> Map.new(&{{&1.metric_type, &1.series_key}, &1})

    cards = Enum.map(Metrics.protobuf_available_types(), &card_for(&1, members, baselines))

    socket
    |> assign(:members, members)
    |> assign(:cards, cards)
  end

  defp card_for(metric_type, members, baselines) do
    baseline = Map.get(baselines, {metric_type, "default"})
    unit = Metrics.metric_unit(metric_type)

    rows =
      Enum.map(members, fn member ->
        current = Baselines.latest_value(member.id, metric_type)
        deviation = if current && baseline, do: current - baseline.mean
        outlier? = outlier?(current, baseline)

        %{
          sensor_name: member.name,
          current_value: current,
          deviation: deviation,
          outlier?: outlier?
        }
      end)

    %{
      metric_type: metric_type,
      label: Metrics.metric_label(metric_type),
      unit: unit,
      baseline: baseline,
      rows: rows,
      summary:
        if(baseline,
          do: "Pool baseline computed from member sensor history.",
          else: "Insufficient sensors for pool baseline."
        )
    }
  end

  defp outlier?(nil, _baseline), do: false
  defp outlier?(_current, nil), do: false

  defp outlier?(current, baseline) do
    Baselines.outliers_from_pool_baseline(baseline, [{"sensor", current}]) != []
  end

  defp format_optional_value(nil, _unit), do: "-"
  defp format_optional_value(value, unit), do: format_value(value, unit)
  defp format_value(value, "%") when is_number(value), do: "#{Float.round(value / 1, 2)}%"

  defp format_value(value, "bytes") when is_number(value),
    do: "#{Float.round(value / 1_048_576, 2)} MB"

  defp format_value(value, unit) when is_number(value), do: "#{Float.round(value / 1, 2)} #{unit}"
  defp format_value(value, _unit), do: to_string(value)
end
