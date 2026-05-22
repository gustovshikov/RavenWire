defmodule ConfigManagerWeb.RuleDeploymentLive do
  @moduledoc """
  Rule deployment LiveView — allows operators to paste Suricata rules and deploy
  them to a specific pod or all pods in a pool.

  Requirements: 7.3, 7.4
  """

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.RulesLive.Helpers, only: [can_deploy_rules?: 1, rules_nav: 1]

  alias ConfigManager.{Audit, Pools, Repo, RuleDeployer, SensorPod}
  import Ecto.Query, only: [from: 2]

  # ── Mount ────────────────────────────────────────────────────────────────────

  @impl true
  def mount(_params, _session, socket) do
    pods = list_enrolled_pods()

    form_params = %{
      "rules" => "",
      "filename" => "local.rules",
      "target" => default_target(pods)
    }

    {:ok,
     assign(socket,
       pods: pods,
       pool_names: Pools.pool_name_map(),
       results: [],
       deploying: false,
       form: to_form(form_params)
     )}
  end

  # ── Events ───────────────────────────────────────────────────────────────────

  @impl true
  def handle_event("deploy", params, socket) do
    rules_content = String.trim(params["rules"] || "")
    filename = String.trim(params["filename"] || "local.rules")
    target = params["target"] || ""

    cond do
      not can_deploy_rules?(socket.assigns.current_user) ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      rules_content == "" ->
        {:noreply,
         assign(socket,
           results: [{:error, "Rules content cannot be empty."}],
           form: to_form(params)
         )}

      true ->
        filename = if filename == "", do: "local.rules", else: filename
        rules_map = %{filename => rules_content}

        socket = assign(socket, deploying: true, results: [], form: to_form(params))

        results = do_deploy(target, rules_map, socket.assigns.pods)
        maybe_log_adhoc_deployment(socket, target, filename, results)

        {:noreply, assign(socket, deploying: false, results: results)}
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────────────

  defp do_deploy("pool:" <> pool_id, rules_map, _pods) do
    case RuleDeployer.deploy_to_pool(pool_id, rules_map) do
      {:ok, pod_results} ->
        Enum.map(pod_results, fn %{pod_name: name, result: result} ->
          format_pod_result(name, result)
        end)
    end
  end

  defp do_deploy(pod_id, rules_map, pods) when pod_id != "" do
    pod_name =
      case Enum.find(pods, fn p -> p.id == pod_id end) do
        nil -> pod_id
        pod -> pod.name
      end

    result = RuleDeployer.deploy_to_pod(pod_id, rules_map)
    [format_pod_result(pod_name, result)]
  end

  defp do_deploy(_, _rules_map, _pods) do
    [{:error, "No target selected."}]
  end

  defp format_pod_result(pod_name, {:ok, _resp}) do
    {:ok, "#{pod_name}: rules deployed successfully."}
  end

  defp format_pod_result(pod_name, {:error, {:validation_error, body}}) do
    msg =
      case body do
        %{"error" => %{"message" => m}} -> m
        %{"error" => m} when is_binary(m) -> m
        _ -> inspect(body)
      end

    {:error, "#{pod_name}: validation failed — #{msg}"}
  end

  defp format_pod_result(pod_name, {:error, :pod_not_found}) do
    {:error, "#{pod_name}: pod not found."}
  end

  defp format_pod_result(pod_name, {:error, reason}) do
    {:error, "#{pod_name}: #{format_reason(reason)}"}
  end

  defp format_reason({:http_error, status, body}), do: "HTTP #{status}: #{body}"
  defp format_reason(reason), do: inspect(reason)

  defp maybe_log_adhoc_deployment(socket, target, filename, results) do
    if Enum.any?(results, &match?({:ok, _message}, &1)) do
      {target_type, target_id, target_label} = audit_target(target, socket.assigns)

      Audit.log(%{
        actor: socket.assigns.current_user.username,
        actor_type: "user",
        action: "adhoc_rules_deployed",
        target_type: target_type,
        target_id: target_id,
        result: "success",
        detail: %{
          target: target_label,
          filename: filename,
          result_count: length(results),
          sensor_results:
            Enum.map(results, fn {status, message} ->
              %{result: Atom.to_string(status), message: message}
            end)
        }
      })
    end
  end

  defp audit_target("pool:" <> pool_id, assigns) do
    {"pool", pool_id, "pool #{Map.get(assigns.pool_names, pool_id, pool_id)}"}
  end

  defp audit_target(pod_id, assigns) do
    pod = Enum.find(assigns.pods, &(&1.id == pod_id))
    {"sensor_pod", pod_id, (pod && pod.name) || pod_id}
  end

  defp list_enrolled_pods do
    Repo.all(from(p in SensorPod, where: p.status == "enrolled", order_by: p.name))
  end

  defp default_target([]), do: ""
  defp default_target([pod | _]), do: pod.id

  defp pool_ids(pods) do
    pods
    |> Enum.map(& &1.pool_id)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  # ── Render ───────────────────────────────────────────────────────────────────

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-3xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Quick Deploy</h1>
        <a href="/" class="text-sm text-blue-600 hover:underline">← Dashboard</a>
      </div>

      <.rules_nav active="quick" />

      <div class="mb-4 rounded border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-900">
        Looking for managed rulesets?
        <a href="/rules/store" class="font-medium text-blue-700 hover:underline">Go to Rule Store</a>
      </div>

      <%= if can_deploy_rules?(@current_user) do %>
      <form phx-submit="deploy" class="bg-white border border-gray-200 rounded-lg shadow-sm p-6 space-y-5">
        <%!-- Rules textarea --%>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Suricata Rules</label>
          <textarea
            name="rules"
            rows="10"
            placeholder="alert tcp any any -> any any (msg:&quot;Example&quot;; sid:1;)"
            class="w-full rounded border border-gray-300 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
          ><%= @form[:rules].value %></textarea>
        </div>

        <%!-- Filename --%>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Filename</label>
          <input
            type="text"
            name="filename"
            value={@form[:filename].value}
            placeholder="local.rules"
            class="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <p class="mt-1 text-xs text-gray-400">Rules will be written to /etc/suricata/rules/&lt;filename&gt;</p>
        </div>

        <%!-- Target selector --%>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Deploy Target</label>
          <select
            name="target"
            class="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <%= for pod <- @pods do %>
              <option value={pod.id} selected={@form[:target].value == pod.id}>
                <%= pod.name %>
              </option>
            <% end %>
            <%= for pool_id <- pool_ids(@pods) do %>
              <option value={"pool:#{pool_id}"} selected={@form[:target].value == "pool:#{pool_id}"}>
                All pods in pool <%= Map.get(@pool_names, pool_id, pool_id) %>
              </option>
            <% end %>
          </select>
          <%= if Enum.empty?(@pods) do %>
            <p class="mt-1 text-xs text-yellow-600">No enrolled pods available.</p>
          <% end %>
        </div>

        <%!-- Submit --%>
        <div class="flex justify-end">
          <button
            type="submit"
            disabled={@deploying}
            class="inline-flex items-center px-4 py-2 rounded text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <%= if @deploying, do: "Deploying…", else: "Deploy Rules" %>
          </button>
        </div>
      </form>
      <% else %>
        <section class="rounded border border-gray-200 bg-white p-6 text-sm text-gray-600">
          You do not have permission to deploy rules.
        </section>
      <% end %>

      <%!-- Results --%>
      <%= if @results != [] do %>
        <div class="mt-6 space-y-2">
          <h2 class="text-sm font-semibold text-gray-700">Deployment Results</h2>
          <%= for result <- @results do %>
            <% {status, msg} = result %>
            <div class={"px-4 py-3 rounded border text-sm #{if status == :ok, do: "bg-green-50 border-green-200 text-green-800", else: "bg-red-50 border-red-200 text-red-800"}"}>
              <%= msg %>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end
end
