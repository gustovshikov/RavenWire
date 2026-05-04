defmodule ConfigManagerWeb.PoolLive.SensorsLive do
  @moduledoc "Pool sensor membership page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers
  alias ConfigManager.Pools
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        if connected?(socket),
          do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}")

        {:ok,
         socket
         |> assign(:not_found, false)
         |> assign(:page_title, "#{pool.name} Sensors")
         |> assign(:pool, pool)
         |> assign(:selected_sensor_ids, [])
         |> assign(:remove_sensor_id, nil)
         |> reload_lists()}
    end
  end

  @impl true
  def handle_info(_message, socket), do: {:noreply, reload_lists(socket)}

  @impl true
  def handle_event("assign", %{"sensor_ids" => sensor_ids}, socket) do
    case Pools.assign_sensors(socket.assigns.pool, sensor_ids, socket.assigns.current_user) do
      {:ok, count} ->
        {:noreply, socket |> put_flash(:info, "Assigned #{count} sensor(s).") |> reload_lists()}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Assignment failed: #{inspect(reason)}")}
    end
  end

  def handle_event("assign", _params, socket),
    do: {:noreply, put_flash(socket, :error, "Select at least one sensor.")}

  def handle_event("remove", %{"sensor-id" => sensor_id}, socket),
    do: {:noreply, assign(socket, remove_sensor_id: sensor_id)}

  def handle_event("cancel_remove", _params, socket),
    do: {:noreply, assign(socket, remove_sensor_id: nil)}

  def handle_event("confirm_remove", %{"sensor-id" => sensor_id}, socket) do
    case Pools.remove_sensors(socket.assigns.pool, [sensor_id], socket.assigns.current_user) do
      {:ok, _count} ->
        {:noreply,
         socket
         |> assign(remove_sensor_id: nil)
         |> put_flash(:info, "Sensor removed from pool.")
         |> reload_lists()}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(remove_sensor_id: nil)
         |> put_flash(:error, "Removal failed: #{inspect(reason)}")}
    end
  end

  defp reload_lists(socket) do
    assign(socket,
      sensors: Pools.list_pool_sensors(socket.assigns.pool.id),
      unassigned_sensors: Pools.list_unassigned_sensors()
    )
  end

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-10">
      <a href="/pools" class="text-sm text-blue-600 hover:underline">Back to pools</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">Pool Not Found</h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-6xl px-6 py-6">
      <a href={"/pools/#{@pool.id}"} class="text-sm text-blue-600 hover:underline">Back to pool</a>
      <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pool.name %> Sensors</h1>
      <p class="mt-1 text-sm text-gray-600">Assignment changes desired state only. It does not automatically push configuration.</p>

      <.pool_nav pool={@pool} />

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <h2 class="mb-3 text-lg font-semibold text-gray-900">Assigned Sensors</h2>
        <%= if @sensors == [] do %>
          <p class="text-sm text-gray-600">No sensors are assigned to this pool.</p>
        <% else %>
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-xs uppercase text-gray-500">
                <th class="py-2 pr-4 font-medium">Sensor</th>
                <th class="py-2 pr-4 font-medium">Status</th>
                <th class="py-2 pr-4 font-medium">Last Seen</th>
                <%= if can_manage_pools?(@current_user) do %>
                  <th class="py-2 font-medium">Action</th>
                <% end %>
              </tr>
            </thead>
            <tbody>
              <%= for sensor <- @sensors do %>
                <tr class="border-b border-gray-100 last:border-0">
                  <th class="py-2 pr-4 font-medium"><a href={"/sensors/#{sensor.id}"} class="text-blue-700 hover:underline"><%= sensor.name %></a></th>
                  <td class="py-2 pr-4"><%= sensor.status %></td>
                  <td class="py-2 pr-4"><%= Formatters.format_utc(sensor.last_seen_at) %></td>
                  <%= if can_manage_pools?(@current_user) do %>
                    <td class="py-2">
                      <button type="button" phx-click="remove" phx-value-sensor-id={sensor.id} class="text-sm text-red-700 hover:underline">Remove from Pool</button>
                    </td>
                  <% end %>
                </tr>
                <%= if @remove_sensor_id == sensor.id do %>
                  <tr>
                    <td colspan="4" class="bg-red-50 px-3 py-3 text-sm text-red-900">
                      Remove <%= sensor.name %> from <%= @pool.name %>?
                      <button type="button" phx-click="confirm_remove" phx-value-sensor-id={sensor.id} class="ml-3 rounded bg-red-700 px-2 py-1 text-xs font-medium text-white">Confirm</button>
                      <button type="button" phx-click="cancel_remove" class="ml-1 rounded border border-gray-300 px-2 py-1 text-xs font-medium text-gray-800">Cancel</button>
                    </td>
                  </tr>
                <% end %>
              <% end %>
            </tbody>
          </table>
        <% end %>
      </section>

      <%= if can_manage_pools?(@current_user) do %>
        <section class="rounded border border-gray-200 bg-white p-4">
          <h2 class="mb-3 text-lg font-semibold text-gray-900">Assign Sensors</h2>
          <%= if @unassigned_sensors == [] do %>
            <p class="text-sm text-gray-600">No enrolled unassigned sensors are available.</p>
          <% else %>
            <form phx-submit="assign" class="space-y-3">
              <%= for sensor <- @unassigned_sensors do %>
                <label class="flex items-center gap-2 text-sm">
                  <input type="checkbox" name="sensor_ids[]" value={sensor.id} />
                  <span><%= sensor.name %></span>
                </label>
              <% end %>
              <button type="submit" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Assign Sensors</button>
            </form>
          <% end %>
        </section>
      <% end %>
    </main>
    """
  end
end
