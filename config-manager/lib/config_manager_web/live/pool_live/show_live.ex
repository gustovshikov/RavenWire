defmodule ConfigManagerWeb.PoolLive.ShowLive do
  @moduledoc "Sensor pool overview page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.DeploymentLive.Helpers,
    only: [drift_summary_label: 1, drift_summary_status: 1, status_class: 1, status_label: 1]

  import ConfigManagerWeb.PoolLive.Helpers
  alias ConfigManager.{Deployments, Pools}
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        if connected?(socket),
          do: subscribe(pool.id)

        {:ok,
         assign(socket,
           not_found: false,
           page_title: pool.name,
           pool: pool,
           member_count: Pools.member_count(pool.id),
           drift_summary: Deployments.drift_summary(pool),
           last_deployment: Deployments.last_deployment(pool.id),
           active_deployment?: Deployments.has_active_deployment?(pool.id),
           confirm_delete: false
         )}
    end
  end

  @impl true
  def handle_info({:pool_deleted, _pool_id}, socket),
    do: {:noreply, push_navigate(socket, to: "/pools")}

  def handle_info(_message, socket) do
    {:noreply, refresh(socket)}
  end

  @impl true
  def handle_event("delete", _params, socket),
    do: {:noreply, assign(socket, confirm_delete: true)}

  def handle_event("cancel_delete", _params, socket),
    do: {:noreply, assign(socket, confirm_delete: false)}

  def handle_event("confirm_delete", _params, socket) do
    case Pools.delete_pool(socket.assigns.pool, socket.assigns.current_user) do
      {:ok, _pool} ->
        {:noreply, push_navigate(socket, to: "/pools")}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(confirm_delete: false)
         |> put_flash(:error, "Delete failed: #{inspect(reason)}")}
    end
  end

  def handle_event("deploy_now", _params, socket) do
    cond do
      not can_manage_deployments?(socket.assigns.current_user) ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      socket.assigns.active_deployment? ->
        {:noreply,
         put_flash(socket, :error, "An active deployment already exists for this pool.")}

      true ->
        case Deployments.create_deployment(socket.assigns.pool, socket.assigns.current_user) do
          {:ok, deployment} ->
            {:noreply,
             socket
             |> put_flash(:info, "Deployment started.")
             |> push_navigate(to: "/deployments/#{deployment.id}")}

          {:error, reason} ->
            {:noreply,
             put_flash(socket, :error, "Deployment failed: #{format_deploy_error(reason)}")}
        end
    end
  end

  defp refresh(socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)

    assign(socket,
      pool: pool,
      member_count: Pools.member_count(pool.id),
      drift_summary: Deployments.drift_summary(pool),
      last_deployment: Deployments.last_deployment(pool.id),
      active_deployment?: Deployments.has_active_deployment?(pool.id)
    )
  end

  defp subscribe(pool_id) do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool_id}")
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool_id}:deployments")
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool_id}:drift")
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
    <main class="mx-auto max-w-5xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <a href="/pools" class="text-sm text-blue-600 hover:underline">Back to pools</a>
          <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pool.name %></h1>
          <p class="text-sm text-gray-500"><%= Formatters.display(@pool.description) %></p>
        </div>
        <%= if can_manage_pools?(@current_user) do %>
          <div class="flex gap-2">
            <a href={"/pools/#{@pool.id}/edit"} class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800 hover:bg-gray-50">Edit Pool</a>
            <button type="button" phx-click="delete" class="rounded border border-red-300 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50">Delete Pool</button>
          </div>
        <% end %>
        <%= if can_manage_deployments?(@current_user) do %>
          <button type="button" phx-click="deploy_now" disabled={@active_deployment?} class="w-fit rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:bg-gray-300 hover:bg-blue-700">Deploy Now</button>
        <% end %>
      </div>

      <.pool_nav pool={@pool} />

      <section class="rounded border border-gray-200 bg-white p-4">
        <h2 class="mb-3 text-lg font-semibold text-gray-900">Pool Overview</h2>
        <dl class="grid gap-3 text-sm md:grid-cols-3">
          <.field label="Capture Mode" value={format_capture_mode(@pool.capture_mode)} />
          <.field label="Members" value={@member_count} />
          <.field label="Config Version" value={@pool.config_version} />
          <div>
            <dt class="text-xs font-medium uppercase text-gray-500">Drift</dt>
            <dd class="mt-1">
              <a href={"/pools/#{@pool.id}/drift"} class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{status_class(drift_summary_status(@drift_summary))}"}>
                <%= drift_summary_label(@drift_summary) %>
              </a>
            </dd>
          </div>
          <div>
            <dt class="text-xs font-medium uppercase text-gray-500">Last Deployment</dt>
            <dd class="mt-1 break-words text-gray-900">
              <%= if @last_deployment do %>
                <a href={"/deployments/#{@last_deployment.id}"} class="text-blue-700 hover:underline">
                  <%= status_label(@last_deployment.status) %>
                </a>
              <% else %>
                <%= Formatters.display(nil) %>
              <% end %>
            </dd>
          </div>
          <.field label="Config Updated At" value={Formatters.format_utc(@pool.config_updated_at)} />
          <.field label="Config Updated By" value={@pool.config_updated_by} />
          <.field label="Created At" value={Formatters.format_utc(@pool.inserted_at)} />
        </dl>
      </section>

      <%= if @confirm_delete do %>
        <section class="mt-4 rounded border border-red-200 bg-red-50 p-4">
          <p class="text-sm font-medium text-red-900">
            Delete pool <%= @pool.name %>? <%= @member_count %> assigned sensor(s) will become unassigned.
          </p>
          <div class="mt-3 flex gap-2">
            <button type="button" phx-click="confirm_delete" class="rounded bg-red-700 px-3 py-2 text-sm font-medium text-white">Confirm Delete</button>
            <button type="button" phx-click="cancel_delete" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800">Cancel</button>
          </div>
        </section>
      <% end %>
    </main>
    """
  end

  defp format_deploy_error(:active_deployment_exists), do: "active deployment exists"
  defp format_deploy_error(:no_deployable_sensors), do: "no deployable sensors"
  defp format_deploy_error(reason), do: inspect(reason)
end
