defmodule ConfigManagerWeb.DeploymentLive.DetailLive do
  @moduledoc "Deployment detail and per-sensor result page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.DeploymentLive.Helpers

  alias ConfigManager.Deployments
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Deployments.get_deployment(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Deployment Not Found")}

      deployment ->
        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "deployment:#{deployment.id}")
        end

        {:ok, assign_detail(socket, deployment)}
    end
  end

  @impl true
  def handle_info(_message, socket) do
    {:noreply, refresh(socket)}
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    if can_manage_deployments?(socket.assigns.current_user) do
      case Deployments.cancel_deployment(socket.assigns.deployment, socket.assigns.current_user) do
        {:ok, _deployment} ->
          {:noreply, socket |> refresh() |> put_flash(:info, "Deployment cancelled.")}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Cancel failed: #{format_error(reason)}")}
      end
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  def handle_event("rollback", _params, socket) do
    if can_manage_deployments?(socket.assigns.current_user) do
      case Deployments.rollback_deployment(socket.assigns.deployment, socket.assigns.current_user) do
        {:ok, rollback} ->
          {:noreply,
           socket
           |> put_flash(:info, "Rollback deployment started.")
           |> push_navigate(to: "/deployments/#{rollback.id}")}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Rollback failed: #{format_error(reason)}")}
      end
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  defp refresh(%{assigns: %{deployment: deployment}} = socket) do
    deployment
    |> then(&Deployments.get_deployment!(&1.id))
    |> then(&assign_detail(socket, &1))
  end

  defp assign_detail(socket, deployment) do
    results = Deployments.list_deployment_results(deployment.id)
    previous = Deployments.previous_successful_deployment(deployment)

    assign(socket,
      not_found: false,
      page_title: "Deployment #{String.slice(deployment.id, 0, 8)}",
      deployment: deployment,
      results: ordered_result_groups(results),
      result_summary: Deployments.result_summary(deployment),
      previous_successful_deployment: previous
    )
  end

  defp ordered_result_groups(results) do
    ["failed", "unreachable", "pushing", "pending", "success", "skipped"]
    |> Enum.flat_map(fn status ->
      case Map.get(results, status, []) do
        [] -> []
        entries -> [{status, entries}]
      end
    end)
  end

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-10">
      <a href="/deployments" class="text-sm text-blue-600 hover:underline">Back to deployments</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">Deployment Not Found</h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <a href="/deployments" class="text-sm text-blue-600 hover:underline">Back to deployments</a>
          <h1 class="mt-2 text-2xl font-bold text-gray-900">Deployment <span class="font-mono"><%= String.slice(@deployment.id, 0, 8) %></span></h1>
          <p class="text-sm text-gray-500">
            <%= if @deployment.pool do %>
              <a href={"/pools/#{@deployment.pool_id}"} class="text-blue-700 hover:underline"><%= @deployment.pool.name %></a>
            <% else %>
              Pool <%= Formatters.display(@deployment.pool_id) %>
            <% end %>
          </p>
        </div>
        <div class="flex flex-wrap gap-2">
          <%= if can_manage_deployments?(@current_user) && active_deployment?(@deployment) do %>
            <button type="button" phx-click="cancel" class="rounded border border-yellow-300 px-3 py-2 text-sm font-medium text-yellow-900 hover:bg-yellow-50">Cancel</button>
          <% end %>
          <%= if can_manage_deployments?(@current_user) && rollback_status?(@deployment) && @previous_successful_deployment do %>
            <button type="button" phx-click="rollback" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Rollback</button>
          <% end %>
        </div>
      </div>

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <div class="mb-3 flex items-center justify-between gap-3">
          <h2 class="text-lg font-semibold text-gray-900">Summary</h2>
          <span class={"inline-flex rounded px-2.5 py-1 text-xs font-medium #{status_class(@deployment.status)}"}>
            <%= status_label(@deployment.status) %>
          </span>
        </div>
        <dl class="grid gap-3 text-sm md:grid-cols-3 lg:grid-cols-6">
          <.field label="Operator" value={@deployment.operator} />
          <.field label="Operator Type" value={status_label(@deployment.operator_type)} />
          <.field label="Config Version" value={@deployment.config_version} />
          <.field label="Forwarding Version" value={@deployment.forwarding_config_version} />
          <.field label="BPF Version" value={@deployment.bpf_version} />
          <.field label="Duration" value={duration(@deployment)} />
          <.field label="Created" value={Formatters.format_utc(@deployment.inserted_at)} />
          <.field label="Started" value={Formatters.format_utc(@deployment.started_at)} />
          <.field label="Completed" value={Formatters.format_utc(@deployment.completed_at)} />
          <.field label="Results" value={result_summary(@result_summary)} />
          <.field label="Rollback Of" value={short_id(@deployment.rollback_of_deployment_id)} />
          <.field label="Source Deployment" value={short_id(@deployment.source_deployment_id)} />
        </dl>
        <%= if @deployment.failure_reason do %>
          <p class="mt-3 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"><%= @deployment.failure_reason %></p>
        <% end %>
      </section>

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <h2 class="mb-3 text-lg font-semibold text-gray-900">Sensor Results</h2>
        <%= if @results == [] do %>
          <p class="text-sm text-gray-600">No sensor results are recorded for this deployment.</p>
        <% else %>
          <div class="space-y-4">
            <%= for {status, results} <- @results do %>
              <div>
                <h3 class="mb-2 text-sm font-semibold text-gray-800">
                  <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{status_class(status)}"}><%= status_label(status) %></span>
                  <span class="ml-2 text-gray-500"><%= length(results) %></span>
                </h3>
                <div class="overflow-x-auto">
                  <table class="w-full text-left text-sm">
                    <thead>
                      <tr class="border-b border-gray-200 text-xs uppercase text-gray-500">
                        <th class="py-2 pr-4 font-medium">Sensor</th>
                        <th class="py-2 pr-4 font-medium">Message</th>
                        <th class="py-2 pr-4 font-medium">Started</th>
                        <th class="py-2 font-medium">Completed</th>
                      </tr>
                    </thead>
                    <tbody>
                      <%= for result <- results do %>
                        <tr class="border-b border-gray-100 last:border-0">
                          <th class="py-2 pr-4 font-medium">
                            <%= if result.sensor_pod do %>
                              <a href={"/sensors/#{result.sensor_pod_id}"} class="text-blue-700 hover:underline"><%= result.sensor_pod.name %></a>
                            <% else %>
                              <span class="font-mono text-xs"><%= result.sensor_pod_id %></span>
                            <% end %>
                          </th>
                          <td class="py-2 pr-4 text-gray-700"><%= Formatters.display(result.message) %></td>
                          <td class="py-2 pr-4 text-gray-700"><%= Formatters.format_utc(result.started_at) %></td>
                          <td class="py-2 text-gray-700"><%= Formatters.format_utc(result.completed_at) %></td>
                        </tr>
                      <% end %>
                    </tbody>
                  </table>
                </div>
              </div>
            <% end %>
          </div>
        <% end %>
      </section>

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <h2 class="mb-3 text-lg font-semibold text-gray-900">Configuration Diff</h2>
        <%= if is_nil(@deployment.diff_summary) do %>
          <p class="text-sm text-gray-600">Initial deployment: no previous successful deployment exists for comparison.</p>
        <% else %>
          <div class="grid gap-3 md:grid-cols-2">
            <%= for {domain, diff} <- @deployment.diff_summary do %>
              <div class="rounded border border-gray-200 p-3">
                <h3 class="mb-2 text-sm font-semibold text-gray-900"><%= status_label(domain) %></h3>
                <pre class="max-h-80 overflow-auto rounded bg-gray-50 p-3 text-xs text-gray-800"><%= json_pretty(diff) %></pre>
              </div>
            <% end %>
          </div>
        <% end %>
      </section>

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <h2 class="mb-3 text-lg font-semibold text-gray-900">Configuration Snapshot</h2>
        <pre class="max-h-96 overflow-auto rounded bg-gray-50 p-3 text-xs text-gray-800"><%= json_pretty(@deployment.config_snapshot) %></pre>
      </section>
    </main>
    """
  end

  attr(:label, :string, required: true)
  attr(:value, :any, required: true)

  def field(assigns) do
    ~H"""
    <div>
      <dt class="text-xs font-medium uppercase text-gray-500"><%= @label %></dt>
      <dd class="mt-1 break-words text-gray-900"><%= Formatters.display(@value) %></dd>
    </div>
    """
  end

  defp short_id(nil), do: nil
  defp short_id(id), do: String.slice(id, 0, 8)

  defp format_error(:active_deployment_exists), do: "active deployment exists"
  defp format_error(:deployment_not_cancellable), do: "deployment is not cancellable"

  defp format_error(:no_previous_successful_deployment),
    do: "no previous successful deployment exists"

  defp format_error(:already_rolled_back), do: "deployment is already rolled back"
  defp format_error(reason), do: inspect(reason)
end
