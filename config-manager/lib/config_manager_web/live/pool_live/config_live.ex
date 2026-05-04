defmodule ConfigManagerWeb.PoolLive.ConfigLive do
  @moduledoc "Pool desired configuration profile page."

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
         assign(socket,
           not_found: false,
           page_title: "#{pool.name} Config",
           pool: pool,
           form: to_form(Pools.change_pool_config(pool))
         )}
    end
  end

  @impl true
  def handle_info({:pool_config_updated, _pool_id}, socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)
    {:noreply, assign(socket, pool: pool, form: to_form(Pools.change_pool_config(pool)))}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def handle_event("validate", %{"sensor_pool" => params}, socket) do
    changeset =
      socket.assigns.pool
      |> Pools.change_pool_config(params, socket.assigns.current_user)
      |> Map.put(:action, :validate)

    {:noreply, assign(socket, form: to_form(changeset))}
  end

  def handle_event("save", %{"sensor_pool" => params}, socket) do
    if can_manage_pools?(socket.assigns.current_user) do
      case Pools.update_pool_config(socket.assigns.pool, params, socket.assigns.current_user) do
        {:ok, pool} ->
          {:noreply,
           socket
           |> assign(pool: pool, form: to_form(Pools.change_pool_config(pool)))
           |> put_flash(:info, "Pool config saved. Deployment remains an explicit action.")}

        {:error, changeset} ->
          {:noreply, assign(socket, form: to_form(%{changeset | action: :update}))}
      end
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
    <main class="mx-auto max-w-4xl px-6 py-6">
      <a href={"/pools/#{@pool.id}"} class="text-sm text-blue-600 hover:underline">Back to pool</a>
      <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pool.name %> Config</h1>
      <p class="mt-1 text-sm text-gray-600">Saving changes updates desired state only. It does not automatically push config to sensors.</p>

      <.pool_nav pool={@pool} />

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <dl class="grid gap-3 text-sm md:grid-cols-3">
          <.field label="Config Version" value={@pool.config_version} />
          <.field label="Updated At" value={Formatters.format_utc(@pool.config_updated_at)} />
          <.field label="Updated By" value={@pool.config_updated_by} />
        </dl>
      </section>

      <.form for={@form} phx-change="validate" phx-submit="save" class="space-y-5 rounded border border-gray-200 bg-white p-6">
        <.select_field field={@form[:capture_mode]} label="Capture Mode" disabled={!can_manage_pools?(@current_user)} options={[{"Alert Driven", "alert_driven"}, {"Full PCAP", "full_pcap"}]} />
        <.number_field field={@form[:pcap_ring_size_mb]} label="PCAP Ring Size MB" disabled={!can_manage_pools?(@current_user)} />
        <.number_field field={@form[:pre_alert_window_sec]} label="Pre-alert Window Seconds" disabled={!can_manage_pools?(@current_user)} />
        <.number_field field={@form[:post_alert_window_sec]} label="Post-alert Window Seconds" disabled={!can_manage_pools?(@current_user)} />
        <.select_field field={@form[:alert_severity_threshold]} label="Alert Severity Threshold" disabled={!can_manage_pools?(@current_user)} options={[{"1 - low", 1}, {"2 - medium", 2}, {"3 - high", 3}]} />

        <%= if can_manage_pools?(@current_user) do %>
          <div class="flex justify-end">
            <button type="submit" class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Save Config</button>
          </div>
        <% end %>
      </.form>
    </main>
    """
  end

  attr(:field, :any, required: true)
  attr(:label, :string, required: true)
  attr(:disabled, :boolean, default: false)

  def number_field(assigns) do
    ~H"""
    <div>
      <label class="mb-1 block text-sm font-medium text-gray-700" for={@field.id}><%= @label %></label>
      <input id={@field.id} name={@field.name} value={@field.value} type="number" disabled={@disabled} class="w-full rounded border border-gray-300 px-3 py-2 text-sm disabled:bg-gray-100" />
      <.field_errors field={@field} />
    </div>
    """
  end

  attr(:field, :any, required: true)
  attr(:label, :string, required: true)
  attr(:disabled, :boolean, default: false)
  attr(:options, :list, required: true)

  def select_field(assigns) do
    ~H"""
    <div>
      <label class="mb-1 block text-sm font-medium text-gray-700" for={@field.id}><%= @label %></label>
      <select id={@field.id} name={@field.name} disabled={@disabled} class="w-full rounded border border-gray-300 px-3 py-2 text-sm disabled:bg-gray-100">
        <%= for {label, value} <- @options do %>
          <option value={value} selected={to_string(@field.value) == to_string(value)}><%= label %></option>
        <% end %>
      </select>
      <.field_errors field={@field} />
    </div>
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
