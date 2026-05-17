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
         |> assign(:remove_sensor_id, nil)
         |> assign(:bulk_remove_sensor_ids, [])
         |> assign(:move_sensor_ids, [])
         |> reload_lists()}
    end
  end

  @impl true
  def handle_info(
        {:sensors_assigned, pool_id, _sensor_ids},
        %{assigns: %{pool: %{id: pool_id}}} = socket
      ),
      do: {:noreply, reload_lists(socket)}

  def handle_info(
        {:sensors_removed, pool_id, _sensor_ids},
        %{assigns: %{pool: %{id: pool_id}}} = socket
      ),
      do: {:noreply, reload_lists(socket)}

  def handle_info({:pool_updated, pool_id}, %{assigns: %{pool: %{id: pool_id}}} = socket),
    do: {:noreply, reload_pool(socket)}

  def handle_info({:pool_deleted, pool_id}, %{assigns: %{pool: %{id: pool_id}}} = socket),
    do: {:noreply, push_navigate(socket, to: "/pools")}

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def handle_event("assign", %{"sensor_ids" => sensor_ids}, socket) do
    require_pool_management(socket, fn ->
      case Pools.assign_sensors(socket.assigns.pool, sensor_ids, socket.assigns.current_user) do
        {:ok, count} ->
          socket |> put_flash(:info, "Assigned #{count} sensor(s).") |> reload_lists()

        {:error, reason} ->
          put_flash(socket, :error, "Assignment failed: #{inspect(reason)}")
      end
    end)
  end

  def handle_event("assign", _params, socket) do
    require_pool_management(socket, fn ->
      put_flash(socket, :error, "Select at least one sensor.")
    end)
  end

  def handle_event("stage_move", %{"sensor_ids" => sensor_ids}, socket) do
    require_pool_management(socket, fn ->
      assign(socket, :move_sensor_ids, List.wrap(sensor_ids))
    end)
  end

  def handle_event("stage_move", _params, socket) do
    require_pool_management(socket, fn ->
      put_flash(socket, :error, "Select at least one sensor to move.")
    end)
  end

  def handle_event("cancel_move", _params, socket) do
    require_pool_management(socket, fn ->
      assign(socket, :move_sensor_ids, [])
    end)
  end

  def handle_event("confirm_move", _params, socket) do
    require_pool_management(socket, fn ->
      sensor_ids = socket.assigns.move_sensor_ids

      case Pools.assign_sensors(socket.assigns.pool, sensor_ids, socket.assigns.current_user,
             allow_reassign?: true
           ) do
        {:ok, count} ->
          socket
          |> assign(move_sensor_ids: [])
          |> put_flash(:info, "Moved #{count} sensor(s) into this pool.")
          |> reload_lists()

        {:error, reason} ->
          socket
          |> assign(move_sensor_ids: [])
          |> put_flash(:error, "Move failed: #{inspect(reason)}")
      end
    end)
  end

  def handle_event("remove", %{"sensor-id" => sensor_id}, socket) do
    require_pool_management(socket, fn ->
      assign(socket, remove_sensor_id: sensor_id)
    end)
  end

  def handle_event("cancel_remove", _params, socket) do
    require_pool_management(socket, fn ->
      assign(socket, remove_sensor_id: nil)
    end)
  end

  def handle_event("confirm_remove", %{"sensor-id" => sensor_id}, socket) do
    require_pool_management(socket, fn ->
      case Pools.remove_sensors(socket.assigns.pool, [sensor_id], socket.assigns.current_user) do
        {:ok, _count} ->
          socket
          |> assign(remove_sensor_id: nil)
          |> put_flash(:info, "Sensor removed from pool.")
          |> reload_lists()

        {:error, reason} ->
          socket
          |> assign(remove_sensor_id: nil)
          |> put_flash(:error, "Removal failed: #{inspect(reason)}")
      end
    end)
  end

  def handle_event("stage_bulk_remove", %{"sensor_ids" => sensor_ids}, socket) do
    require_pool_management(socket, fn ->
      assign(socket, :bulk_remove_sensor_ids, List.wrap(sensor_ids))
    end)
  end

  def handle_event("stage_bulk_remove", _params, socket) do
    require_pool_management(socket, fn ->
      put_flash(socket, :error, "Select at least one sensor to remove.")
    end)
  end

  def handle_event("cancel_bulk_remove", _params, socket) do
    require_pool_management(socket, fn ->
      assign(socket, :bulk_remove_sensor_ids, [])
    end)
  end

  def handle_event("confirm_bulk_remove", _params, socket) do
    require_pool_management(socket, fn ->
      sensor_ids = socket.assigns.bulk_remove_sensor_ids

      case Pools.remove_sensors(socket.assigns.pool, sensor_ids, socket.assigns.current_user) do
        {:ok, count} ->
          socket
          |> assign(bulk_remove_sensor_ids: [])
          |> put_flash(:info, "Removed #{count} sensor(s) from pool.")
          |> reload_lists()

        {:error, reason} ->
          socket
          |> assign(bulk_remove_sensor_ids: [])
          |> put_flash(:error, "Bulk removal failed: #{inspect(reason)}")
      end
    end)
  end

  defp reload_lists(socket) do
    assign(socket,
      sensors: Pools.list_pool_sensors(socket.assigns.pool.id),
      unassigned_sensors: Pools.list_unassigned_sensors(),
      other_pool_sensors: Pools.list_other_pool_sensors(socket.assigns.pool.id)
    )
  end

  defp reload_pool(socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)

    socket
    |> assign(:pool, pool)
    |> assign(:page_title, "#{pool.name} Sensors")
    |> reload_lists()
  end

  defp require_pool_management(socket, fun) do
    if can_manage_pools?(socket.assigns.current_user) do
      {:noreply, fun.()}
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
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

      <section aria-label="Assigned Sensors" class="mb-4 rounded border border-gray-200 bg-white p-4">
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
                      <button type="button" phx-click="remove" phx-value-sensor-id={sensor.id} aria-label={"Remove #{sensor.name} from pool"} class="text-sm text-red-700 hover:underline">Remove from Pool</button>
                    </td>
                  <% end %>
                </tr>
                <%= if @remove_sensor_id == sensor.id do %>
                  <tr>
                    <td colspan="4" class="bg-red-50 px-3 py-3 text-sm text-red-900">
                      Remove <%= sensor.name %> from <%= @pool.name %>?
                      <button type="button" phx-click="confirm_remove" phx-value-sensor-id={sensor.id} aria-label={"Confirm removal of #{sensor.name}"} class="ml-3 rounded bg-red-700 px-2 py-1 text-xs font-medium text-white">Confirm</button>
                      <button type="button" phx-click="cancel_remove" aria-label="Cancel sensor removal" class="ml-1 rounded border border-gray-300 px-2 py-1 text-xs font-medium text-gray-800">Cancel</button>
                    </td>
                  </tr>
                <% end %>
              <% end %>
            </tbody>
          </table>
        <% end %>
      </section>

      <%= if can_manage_pools?(@current_user) do %>
        <section aria-label="Assign Unassigned Sensors" class="mb-4 rounded border border-gray-200 bg-white p-4">
          <h2 class="mb-3 text-lg font-semibold text-gray-900">Assign Sensors</h2>
          <%= if @unassigned_sensors == [] do %>
            <p class="text-sm text-gray-600">No enrolled unassigned sensors are available.</p>
          <% else %>
            <form phx-submit="assign" aria-label="Assign unassigned sensors to pool" class="space-y-3">
              <%= for sensor <- @unassigned_sensors do %>
                <label class="flex items-center gap-2 text-sm">
                  <input type="checkbox" name="sensor_ids[]" value={sensor.id} />
                  <span><%= sensor.name %></span>
                </label>
              <% end %>
              <button type="submit" aria-label="Assign selected unassigned sensors" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Assign Sensors</button>
            </form>
          <% end %>
        </section>

        <section aria-label="Move Sensors From Other Pools" class="mb-4 rounded border border-gray-200 bg-white p-4">
          <h2 class="mb-3 text-lg font-semibold text-gray-900">Move from Another Pool</h2>
          <%= if @other_pool_sensors == [] do %>
            <p class="text-sm text-gray-600">No enrolled sensors are assigned to other pools.</p>
          <% else %>
            <form phx-submit="stage_move" aria-label="Move sensors from another pool" class="space-y-3">
              <%= for sensor <- @other_pool_sensors do %>
                <label class="flex items-center gap-2 text-sm">
                  <input type="checkbox" name="sensor_ids[]" value={sensor.id} />
                  <span><%= sensor.name %> <span class="text-gray-500">from <%= pool_label(sensor.pool_id) %></span></span>
                </label>
              <% end %>
              <button type="submit" aria-label="Review selected sensors for move" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Move Selected Sensors</button>
            </form>
          <% end %>

          <%= if @move_sensor_ids != [] do %>
            <div class="mt-4 rounded border border-yellow-200 bg-yellow-50 p-3 text-sm text-yellow-900">
              Move <%= length(@move_sensor_ids) %> sensor(s) into <%= @pool.name %>? This will remove them from their current pool.
              <div class="mt-3 flex gap-2">
                <button type="button" phx-click="confirm_move" aria-label="Confirm sensor move" class="rounded bg-yellow-700 px-3 py-2 text-sm font-medium text-white">Confirm Move</button>
                <button type="button" phx-click="cancel_move" aria-label="Cancel sensor move" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800">Cancel</button>
              </div>
            </div>
          <% end %>
        </section>

        <section aria-label="Bulk Remove Sensors" class="rounded border border-gray-200 bg-white p-4">
          <h2 class="mb-3 text-lg font-semibold text-gray-900">Bulk Remove</h2>
          <%= if @sensors == [] do %>
            <p class="text-sm text-gray-600">No assigned sensors are available for bulk removal.</p>
          <% else %>
            <form phx-submit="stage_bulk_remove" aria-label="Remove multiple sensors from pool" class="space-y-3">
              <%= for sensor <- @sensors do %>
                <label class="flex items-center gap-2 text-sm">
                  <input type="checkbox" name="sensor_ids[]" value={sensor.id} />
                  <span><%= sensor.name %></span>
                </label>
              <% end %>
              <button type="submit" aria-label="Review selected sensors for removal" class="rounded border border-red-300 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50">Remove Selected Sensors</button>
            </form>
          <% end %>

          <%= if @bulk_remove_sensor_ids != [] do %>
            <div class="mt-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-900">
              Remove <%= length(@bulk_remove_sensor_ids) %> sensor(s) from <%= @pool.name %>?
              <div class="mt-3 flex gap-2">
                <button type="button" phx-click="confirm_bulk_remove" aria-label="Confirm bulk sensor removal" class="rounded bg-red-700 px-3 py-2 text-sm font-medium text-white">Confirm Remove</button>
                <button type="button" phx-click="cancel_bulk_remove" aria-label="Cancel bulk sensor removal" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800">Cancel</button>
              </div>
            </div>
          <% end %>
        </section>
      <% end %>
    </main>
    """
  end

  defp pool_label(nil), do: "another pool"

  defp pool_label(pool_id) do
    Pools.pool_name(pool_id) || "another pool"
  end
end
