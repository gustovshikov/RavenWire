defmodule ConfigManagerWeb.PoolLive.DeploymentsLive do
  @moduledoc "Pool deployment history page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.DeploymentLive.Helpers,
    only: [duration: 1, result_summary: 1, status_class: 1, status_label: 1]

  import ConfigManagerWeb.PoolLive.Helpers
  alias ConfigManager.{Deployments, Pools}
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id} = params, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        if connected?(socket),
          do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}:deployments")

        page = params["page"] || 1
        deployments = Deployments.list_pool_deployments(pool.id, page: page)

        {:ok,
         assign(socket,
           not_found: false,
           page_title: "#{pool.name} Deployments",
           pool: pool,
           active_deployment?: Deployments.has_active_deployment?(pool.id),
           deployments: deployments
         )}
    end
  end

  @impl true
  def handle_info(_message, socket), do: {:noreply, refresh(socket)}

  @impl true
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
            {:noreply, put_flash(socket, :error, "Deployment failed: #{format_error(reason)}")}
        end
    end
  end

  defp refresh(socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)

    assign(socket,
      pool: pool,
      active_deployment?: Deployments.has_active_deployment?(pool.id),
      deployments:
        Deployments.list_pool_deployments(pool.id, page: socket.assigns.deployments.page)
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
    <main class="mx-auto max-w-5xl px-6 py-6">
      <div class="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <a href={"/pools/#{@pool.id}"} class="text-sm text-blue-600 hover:underline">Back to pool</a>
          <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pool.name %> Deployments</h1>
        </div>
        <%= if can_manage_deployments?(@current_user) do %>
          <button type="button" phx-click="deploy_now" disabled={@active_deployment?} class="w-fit rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:bg-gray-300 hover:bg-blue-700">Deploy Now</button>
        <% end %>
      </div>

      <.pool_nav pool={@pool} />

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @deployments.entries == [] do %>
          <p class="p-6 text-sm text-gray-600">No deployments have been recorded for this pool.</p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                  <th class="px-4 py-3 font-medium">Deployment</th>
                  <th class="px-4 py-3 font-medium">Status</th>
                  <th class="px-4 py-3 font-medium">Versions</th>
                  <th class="px-4 py-3 font-medium">Results</th>
                  <th class="px-4 py-3 font-medium">Operator</th>
                  <th class="px-4 py-3 font-medium">Started</th>
                  <th class="px-4 py-3 font-medium">Duration</th>
                </tr>
              </thead>
              <tbody>
                <%= for deployment <- @deployments.entries do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <th class="px-4 py-3 font-mono text-xs font-medium">
                      <a href={"/deployments/#{deployment.id}"} class="text-blue-700 hover:underline"><%= String.slice(deployment.id, 0, 8) %></a>
                    </th>
                    <td class="px-4 py-3">
                      <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{status_class(deployment.status)}"}>
                        <%= status_label(deployment.status) %>
                      </span>
                    </td>
                    <td class="px-4 py-3 text-gray-700">
                      C<%= deployment.config_version %> / F<%= Formatters.display(deployment.forwarding_config_version) %> / B<%= Formatters.display(deployment.bpf_version) %>
                    </td>
                    <td class="px-4 py-3 text-gray-700"><%= result_summary(Deployments.result_summary(deployment)) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= deployment.operator %></td>
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.format_utc(deployment.started_at || deployment.inserted_at) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= duration(deployment) %></td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </section>
    </main>
    """
  end

  defp format_error(:active_deployment_exists), do: "active deployment exists"
  defp format_error(:no_deployable_sensors), do: "no deployable sensors"
  defp format_error(reason), do: inspect(reason)
end
