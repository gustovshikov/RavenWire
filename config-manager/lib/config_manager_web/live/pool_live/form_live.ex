defmodule ConfigManagerWeb.PoolLive.FormLive do
  @moduledoc "Sensor pool create and edit form."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.{Pools, SensorPool}

  @impl true
  def mount(params, _session, socket) do
    case socket.assigns.live_action do
      :new ->
        changeset =
          Pools.change_pool(
            %SensorPool{},
            %{"capture_mode" => "alert_driven"},
            socket.assigns.current_user
          )

        {:ok,
         assign(socket,
           page_title: "Create Pool",
           pool: %SensorPool{},
           form: to_form(changeset),
           action: :new
         )}

      :edit ->
        with %SensorPool{} = pool <- Pools.get_pool(params["id"]) do
          {:ok,
           assign(socket,
             page_title: "Edit #{pool.name}",
             pool: pool,
             form: to_form(Pools.change_pool_metadata(pool)),
             action: :edit
           )}
        else
          nil -> {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}
        end
    end
  end

  @impl true
  def handle_event("validate", %{"sensor_pool" => params}, socket) do
    changeset =
      case socket.assigns.action do
        :new -> Pools.change_pool(socket.assigns.pool, params, socket.assigns.current_user)
        :edit -> Pools.change_pool_metadata(socket.assigns.pool, params)
      end
      |> Map.put(:action, :validate)

    {:noreply, assign(socket, form: to_form(changeset))}
  end

  def handle_event("save", %{"sensor_pool" => params}, socket) do
    save_pool(socket, socket.assigns.action, params)
  end

  defp save_pool(socket, :new, params) do
    case Pools.create_pool(params, socket.assigns.current_user) do
      {:ok, pool} ->
        {:noreply, push_navigate(socket, to: "/pools/#{pool.id}")}

      {:error, changeset} ->
        {:noreply, assign(socket, form: to_form(%{changeset | action: :insert}))}
    end
  end

  defp save_pool(socket, :edit, params) do
    case Pools.update_pool(socket.assigns.pool, params, socket.assigns.current_user) do
      {:ok, pool} ->
        {:noreply, push_navigate(socket, to: "/pools/#{pool.id}")}

      {:error, changeset} ->
        {:noreply, assign(socket, form: to_form(%{changeset | action: :update}))}
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
    <main class="mx-auto max-w-3xl px-6 py-6">
      <div class="mb-6">
        <a href="/pools" class="text-sm text-blue-600 hover:underline">Back to pools</a>
        <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @page_title %></h1>
      </div>

      <.form for={@form} phx-change="validate" phx-submit="save" class="space-y-5 rounded border border-gray-200 bg-white p-6">
        <div>
          <label class="mb-1 block text-sm font-medium text-gray-700" for="sensor_pool_name">Pool Name</label>
          <input id="sensor_pool_name" name="sensor_pool[name]" value={@form[:name].value} required class="w-full rounded border border-gray-300 px-3 py-2 text-sm" />
          <p class="mt-1 text-xs text-gray-500">Use letters, numbers, hyphens, underscores, and periods.</p>
          <.field_errors field={@form[:name]} />
        </div>
        <div>
          <label class="mb-1 block text-sm font-medium text-gray-700" for="sensor_pool_description">Description</label>
          <textarea id="sensor_pool_description" name="sensor_pool[description]" rows="4" class="w-full rounded border border-gray-300 px-3 py-2 text-sm"><%= @form[:description].value %></textarea>
          <.field_errors field={@form[:description]} />
        </div>

        <%= if @action == :new do %>
          <div>
            <label class="mb-1 block text-sm font-medium text-gray-700" for="sensor_pool_capture_mode">Capture Mode</label>
            <select id="sensor_pool_capture_mode" name="sensor_pool[capture_mode]" class="w-full rounded border border-gray-300 px-3 py-2 text-sm">
              <option value="alert_driven" selected={@form[:capture_mode].value == "alert_driven"}>Alert Driven</option>
              <option value="full_pcap" selected={@form[:capture_mode].value == "full_pcap"}>Full PCAP</option>
            </select>
            <.field_errors field={@form[:capture_mode]} />
          </div>
        <% end %>

        <div class="flex justify-end">
          <button type="submit" class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Save Pool</button>
        </div>
      </.form>
    </main>
    """
  end

  attr(:field, :any, required: true)

  def field_errors(assigns) do
    ~H"""
    <%= for error <- @field.errors do %>
      <p class="mt-1 text-xs text-red-700"><%= translate_error(error) %></p>
    <% end %>
    """
  end

  defp translate_error({message, opts}) do
    Enum.reduce(opts, message, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", to_string(value))
    end)
  end
end
