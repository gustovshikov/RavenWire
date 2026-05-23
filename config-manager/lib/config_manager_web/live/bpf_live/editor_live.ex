defmodule ConfigManagerWeb.BpfLive.EditorLive do
  @moduledoc "Pool-level BPF filter editor."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers

  alias ConfigManager.Bpf
  alias ConfigManager.Bpf.RuleParams
  alias ConfigManager.{Audit, Pools}
  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.Formatters

  @default_rule_form %{
    index: nil,
    rule_type: "port_exclusion",
    label: "",
    enabled: true,
    src_cidr: "",
    dst_cidr: "",
    port: "",
    port_end: "",
    protocol: "any",
    errors: []
  }

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}:bpf")
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_pods")
        end

        {:ok,
         socket
         |> assign(:not_found, false)
         |> assign(:page_title, "#{pool.name} BPF Filters")
         |> assign(:pool, pool)
         |> load_state()}
    end
  end

  @impl true
  def handle_info({event, _pool_id}, socket)
      when event in [:bpf_profile_created, :bpf_profile_updated, :bpf_profile_reset],
      do: {:noreply, load_state(socket)}

  def handle_info({:pod_degraded, _pod_id, :bpf_restart_pending, _value}, socket),
    do: {:noreply, load_restart_pending(socket)}

  def handle_info({:pod_recovered, _pod_id, :bpf_restart_pending}, socket),
    do: {:noreply, load_restart_pending(socket)}

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def handle_event("create_profile", _params, socket) do
    with :ok <- authorize_bpf(socket),
         {:ok, _profile} <-
           Bpf.create_profile(socket.assigns.pool.id, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "BPF profile created.")
       |> load_state()}
    else
      {:error, :forbidden} ->
        {:noreply, deny(socket, "create_profile")}

      {:error, :profile_exists} ->
        {:noreply, socket |> put_flash(:info, "BPF profile already exists.") |> load_state()}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Create failed: #{format_error(reason)}")}
    end
  end

  def handle_event("add_rule", _params, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      {:noreply, assign(socket, :rule_form, @default_rule_form)}
    else
      {:noreply, deny(socket, "add_rule")}
    end
  end

  def handle_event("edit_rule", %{"index" => index}, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      rule = Enum.at(socket.assigns.rules, to_int(index, -1))
      {:noreply, assign(socket, :rule_form, rule_form(rule, to_int(index, nil)))}
    else
      {:noreply, deny(socket, "edit_rule")}
    end
  end

  def handle_event("cancel_rule", _params, socket),
    do: {:noreply, assign(socket, :rule_form, nil)}

  def handle_event("save_rule", %{"rule" => params}, socket) do
    with :ok <- authorize_bpf(socket),
         {:ok, rule, index} <- parse_rule_form(params) do
      rules =
        socket.assigns.rules
        |> upsert_rule(rule, index)
        |> normalize_positions()

      {:noreply,
       socket
       |> assign(rules: rules, rule_form: nil, dirty: true, validation_result: nil)
       |> update_preview()}
    else
      {:error, :forbidden} ->
        {:noreply, deny(socket, "save_rule")}

      {:error, form} when is_map(form) ->
        {:noreply, assign(socket, :rule_form, form)}
    end
  end

  def handle_event("delete_rule", %{"index" => index}, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      rules =
        socket.assigns.rules
        |> List.delete_at(to_int(index, -1))
        |> normalize_positions()

      {:noreply,
       socket
       |> assign(rules: rules, dirty: true, validation_result: nil)
       |> update_preview()}
    else
      {:noreply, deny(socket, "delete_rule")}
    end
  end

  def handle_event("toggle_rule", %{"index" => index}, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      rules =
        update_rule_at(socket.assigns.rules, to_int(index, -1), fn rule ->
          %{rule | enabled: !rule.enabled}
        end)

      {:noreply,
       socket
       |> assign(rules: rules, dirty: true, validation_result: nil)
       |> update_preview()}
    else
      {:noreply, deny(socket, "toggle_rule")}
    end
  end

  def handle_event("reorder_rules", %{"index" => index, "direction" => direction}, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      rules =
        socket.assigns.rules
        |> move_rule(to_int(index, -1), direction)
        |> normalize_positions()

      {:noreply,
       socket
       |> assign(rules: rules, dirty: true, validation_result: nil)
       |> update_preview()}
    else
      {:noreply, deny(socket, "reorder_rules")}
    end
  end

  def handle_event("update_raw_expression", params, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      {:noreply,
       socket
       |> assign(raw_expression: Map.get(params, "raw_expression", ""))
       |> assign(dirty: true, validation_result: nil)
       |> update_preview()}
    else
      {:noreply, deny(socket, "update_raw_expression")}
    end
  end

  def handle_event("update_composition_mode", params, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      mode = Map.get(params, "composition_mode", "append")

      {:noreply,
       socket
       |> assign(composition_mode: mode, dirty: true, validation_result: nil)
       |> update_preview()}
    else
      {:noreply, deny(socket, "update_composition_mode")}
    end
  end

  def handle_event("validate", _params, socket) do
    with :ok <- authorize_bpf(socket),
         {:ok, result} <- Bpf.validate_expression(socket.assigns.compiled_expression) do
      {:noreply, assign(socket, validation_result: {:ok, result}, validating: false)}
    else
      {:error, :forbidden} ->
        {:noreply, deny(socket, "validate")}

      {:error, reason} ->
        {:noreply, assign(socket, validation_result: {:error, reason}, validating: false)}
    end
  end

  def handle_event("save", _params, socket) do
    with :ok <- authorize_bpf(socket),
         false <- is_nil(socket.assigns.profile),
         {:ok, _profile} <-
           Bpf.save_profile(
             socket.assigns.profile,
             profile_params(socket),
             socket.assigns.current_user
           ) do
      {:noreply,
       socket
       |> put_flash(:info, "BPF profile saved. Changes are not deployed until deployment runs.")
       |> load_state()}
    else
      {:error, :forbidden} ->
        {:noreply, deny(socket, "save")}

      true ->
        {:noreply, put_flash(socket, :error, "Create a BPF profile first.")}

      {:error, :compilation_timeout} ->
        {:noreply, put_flash(socket, :error, "BPF validation timed out.")}

      {:error, {:compilation_failed, %{message: message}}} ->
        {:noreply, put_flash(socket, :error, "BPF validation failed: #{message}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Save failed: #{format_error(reason)}")}
    end
  end

  def handle_event("reset", _params, socket) do
    if can_manage_bpf?(socket.assigns.current_user) do
      {:noreply, assign(socket, :show_reset_confirm, true)}
    else
      {:noreply, deny(socket, "reset")}
    end
  end

  def handle_event("cancel_reset", _params, socket),
    do: {:noreply, assign(socket, :show_reset_confirm, false)}

  def handle_event("confirm_reset", _params, %{assigns: %{profile: nil}} = socket),
    do: {:noreply, assign(socket, :show_reset_confirm, false)}

  def handle_event("confirm_reset", _params, socket) do
    with :ok <- authorize_bpf(socket),
         {:ok, _profile} <- Bpf.reset_profile(socket.assigns.profile, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "BPF profile reset.")
       |> load_state()}
    else
      {:error, :forbidden} ->
        {:noreply, deny(socket, "reset")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Reset failed: #{format_error(reason)}")}
    end
  end

  defp load_state(socket) do
    pool = socket.assigns.pool
    profile = Bpf.get_profile_for_pool(pool.id)
    rules = if profile, do: Bpf.list_rules(profile.id) |> Enum.map(&rule_to_map/1), else: []
    raw_expression = (profile && profile.raw_expression) || ""
    composition_mode = (profile && profile.composition_mode) || "append"
    compiled_expression = Bpf.generate_expression(rules, raw_expression, composition_mode)
    summary = Bpf.bpf_summary(pool.id)
    restart = Bpf.bpf_restart_pending_sensors(pool.id)

    assign(socket,
      profile: profile,
      rules: rules,
      raw_expression: raw_expression,
      composition_mode: composition_mode,
      compiled_expression: compiled_expression,
      validation_result: nil,
      validating: false,
      restart_pending_sensors: restart.sensors,
      restart_pending_count: restart.count,
      pending_deployment: summary.pending_deployment,
      dirty: false,
      rule_form: nil,
      show_reset_confirm: false
    )
  end

  defp load_restart_pending(socket) do
    restart = Bpf.bpf_restart_pending_sensors(socket.assigns.pool.id)

    assign(socket,
      restart_pending_sensors: restart.sensors,
      restart_pending_count: restart.count
    )
  end

  defp update_preview(socket) do
    assign(
      socket,
      :compiled_expression,
      Bpf.generate_expression(
        socket.assigns.rules,
        socket.assigns.raw_expression,
        socket.assigns.composition_mode
      )
    )
  end

  defp rule_to_map(rule) do
    %{
      rule_type: rule.rule_type,
      params: rule.params || %{},
      label: rule.label,
      enabled: rule.enabled,
      position: rule.position || 0
    }
  end

  defp profile_params(socket) do
    %{
      rules: socket.assigns.rules,
      raw_expression: socket.assigns.raw_expression,
      composition_mode: socket.assigns.composition_mode
    }
  end

  defp parse_rule_form(params) do
    form = normalize_form(params)
    params_map = rule_params(form.rule_type, form)

    case RuleParams.validate(form.rule_type, params_map) do
      :ok ->
        {:ok,
         %{
           rule_type: form.rule_type,
           params: params_map,
           label: blank_to_nil(form.label),
           enabled: form.enabled,
           position: 0
         }, form.index}

      {:error, message} ->
        {:error, %{form | errors: [message]}}
    end
  end

  defp normalize_form(params) do
    %{
      index: string_index(Map.get(params, "index")),
      rule_type: Map.get(params, "rule_type", "port_exclusion"),
      label: Map.get(params, "label", "") |> to_string() |> String.trim(),
      enabled: truthy?(Map.get(params, "enabled", "false")),
      src_cidr: Map.get(params, "src_cidr", "") |> to_string() |> String.trim(),
      dst_cidr: Map.get(params, "dst_cidr", "") |> to_string() |> String.trim(),
      port: Map.get(params, "port", "") |> to_string() |> String.trim(),
      port_end: Map.get(params, "port_end", "") |> to_string() |> String.trim(),
      protocol: Map.get(params, "protocol", "any"),
      errors: []
    }
  end

  defp rule_params("cidr_pair", form) do
    clean(%{"src_cidr" => form.src_cidr, "dst_cidr" => form.dst_cidr})
  end

  defp rule_params("elephant_flow", form) do
    clean(%{
      "src_cidr" => form.src_cidr,
      "dst_cidr" => form.dst_cidr,
      "port" => form.port,
      "port_end" => form.port_end,
      "protocol" => form.protocol
    })
  end

  defp rule_params("port_exclusion", form) do
    clean(%{"port" => form.port, "port_end" => form.port_end, "protocol" => form.protocol})
  end

  defp rule_params(_rule_type, _form), do: %{}

  defp clean(params) do
    params
    |> Enum.reject(fn {_key, value} -> value in [nil, ""] end)
    |> Map.new()
  end

  defp rule_form(nil, _index), do: @default_rule_form

  defp rule_form(rule, index) do
    params = rule.params || %{}

    %{
      @default_rule_form
      | index: index,
        rule_type: rule.rule_type,
        label: rule.label || "",
        enabled: rule.enabled,
        src_cidr: Map.get(params, "src_cidr", ""),
        dst_cidr: Map.get(params, "dst_cidr", ""),
        port: Map.get(params, "port", ""),
        port_end: Map.get(params, "port_end", ""),
        protocol: Map.get(params, "protocol", "any")
    }
  end

  defp upsert_rule(rules, rule, nil), do: rules ++ [rule]

  defp upsert_rule(rules, rule, index) do
    List.replace_at(rules, index, %{rule | position: index})
  end

  defp update_rule_at(rules, index, fun) when index >= 0 do
    rules
    |> Enum.with_index()
    |> Enum.map(fn
      {rule, ^index} -> fun.(rule)
      {rule, _other_index} -> rule
    end)
  end

  defp update_rule_at(rules, _index, _fun), do: rules

  defp move_rule(rules, index, "up") when index > 0 do
    rules
    |> List.replace_at(index - 1, Enum.at(rules, index))
    |> List.replace_at(index, Enum.at(rules, index - 1))
  end

  defp move_rule(rules, index, "down") when index >= 0 and index < length(rules) - 1 do
    rules
    |> List.replace_at(index, Enum.at(rules, index + 1))
    |> List.replace_at(index + 1, Enum.at(rules, index))
  end

  defp move_rule(rules, _index, _direction), do: rules

  defp normalize_positions(rules) do
    rules
    |> Enum.with_index()
    |> Enum.map(fn {rule, index} -> %{rule | position: index} end)
  end

  defp deny(socket, action) do
    Audit.log(%{
      actor: actor_name(socket.assigns.current_user),
      actor_type: "user",
      action: "permission_denied",
      target_type: "bpf_profile",
      target_id: denied_target_id(socket),
      result: "failure",
      detail: %{required_permission: "bpf:manage", action: action}
    })

    put_flash(socket, :error, "Insufficient permissions.")
  end

  defp denied_target_id(%{assigns: %{profile: %{id: id}}}), do: id
  defp denied_target_id(%{assigns: %{pool: %{id: id}}}), do: id

  defp authorize_bpf(socket) do
    if can_manage_bpf?(socket.assigns.current_user), do: :ok, else: {:error, :forbidden}
  end

  defp can_manage_bpf?(nil), do: false
  defp can_manage_bpf?(user), do: Policy.has_permission?(user.role, "bpf:manage")

  defp validation_class({:ok, _result}), do: "border-green-200 bg-green-50 text-green-800"
  defp validation_class({:error, _reason}), do: "border-red-200 bg-red-50 text-red-800"

  defp validation_message({:ok, %{instruction_count: count}}),
    do: "Valid BPF expression. #{count} instruction(s)."

  defp validation_message({:error, %{message: message}}), do: "Invalid BPF expression: #{message}"
  defp validation_message({:error, reason}), do: "Invalid BPF expression: #{format_error(reason)}"

  defp rule_type_label("cidr_pair"), do: "CIDR Pair"
  defp rule_type_label("elephant_flow"), do: "Elephant Flow"
  defp rule_type_label("port_exclusion"), do: "Port Exclusion"
  defp rule_type_label(value), do: Formatters.display(value)

  defp rule_summary(%{rule_type: "cidr_pair", params: params}) do
    "src #{Map.get(params, "src_cidr")} -> dst #{Map.get(params, "dst_cidr")}"
  end

  defp rule_summary(%{rule_type: "elephant_flow", params: params}) do
    params
    |> common_summary_parts()
    |> Enum.join(", ")
  end

  defp rule_summary(%{rule_type: "port_exclusion", params: params}) do
    params
    |> port_summary_parts()
    |> Enum.join(", ")
  end

  defp rule_summary(_rule), do: "Unknown rule"

  defp common_summary_parts(params) do
    [
      if(Map.get(params, "src_cidr"), do: "src #{Map.get(params, "src_cidr")}"),
      if(Map.get(params, "dst_cidr"), do: "dst #{Map.get(params, "dst_cidr")}")
    ]
    |> Enum.reject(&is_nil/1)
    |> Kernel.++(port_summary_parts(params))
  end

  defp port_summary_parts(params) do
    [
      port_label(params),
      protocol_label(Map.get(params, "protocol"))
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp port_label(%{"port" => port, "port_end" => port_end}), do: "ports #{port}-#{port_end}"
  defp port_label(%{"port" => port}), do: "port #{port}"
  defp port_label(_params), do: nil

  defp protocol_label(protocol) when protocol in ["tcp", "udp"], do: protocol
  defp protocol_label(_protocol), do: nil

  defp raw_display(""), do: Formatters.display(nil)
  defp raw_display(nil), do: Formatters.display(nil)
  defp raw_display(value), do: value

  defp pending_label(true), do: "Saved changes pending deployment"
  defp pending_label(false), do: "No pending BPF deployment"

  defp pending_class(true), do: "bg-yellow-100 text-yellow-800"
  defp pending_class(false), do: "bg-green-100 text-green-800"

  defp format_error(%Ecto.Changeset{} = changeset) do
    changeset.errors
    |> Enum.map(fn {field, {message, _opts}} -> "#{field} #{message}" end)
    |> Enum.join(", ")
  end

  defp format_error(reason), do: inspect(reason)

  defp string_index(nil), do: nil
  defp string_index(""), do: nil
  defp string_index(value), do: to_int(value, nil)

  defp to_int(value, _default) when is_integer(value), do: value

  defp to_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} -> int
      _other -> default
    end
  end

  defp to_int(_value, default), do: default

  defp truthy?(value), do: value in [true, "true", "1", 1, "on"]

  defp blank_to_nil(nil), do: nil
  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  defp actor_name(%{username: username}) when is_binary(username), do: username
  defp actor_name(_user), do: "system"

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
      <div class="mt-2 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900"><%= @pool.name %> BPF Filters</h1>
          <p class="text-sm text-gray-500">Versioned capture filter profile for this pool.</p>
        </div>
        <%= if @profile do %>
          <span class={"w-fit rounded px-2 py-1 text-xs font-medium #{pending_class(@pending_deployment)}"}>
            <%= pending_label(@pending_deployment) %>
          </span>
        <% end %>
      </div>

      <.pool_nav pool={@pool} />

      <%= if is_nil(@profile) do %>
        <section class="rounded border border-gray-200 bg-white p-6">
          <h2 class="text-lg font-semibold text-gray-900">BPF Filter Profile</h2>
          <p class="mt-2 text-sm text-gray-600">No BPF profile exists for this pool.</p>
          <%= if can_manage_bpf?(@current_user) do %>
            <button type="button" phx-click="create_profile" class="mt-4 rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Create Profile</button>
          <% end %>
        </section>
      <% else %>
        <section class="mb-4 rounded border border-gray-200 bg-white p-4">
          <dl class="grid gap-3 text-sm md:grid-cols-4">
            <.field label="Version" value={@profile.version} />
            <.field label="Last Deployed" value={@profile.last_deployed_version} />
            <.field label="Updated At" value={Formatters.format_utc(@profile.updated_at)} />
            <.field label="Updated By" value={@profile.updated_by} />
          </dl>
        </section>

        <%= if @restart_pending_count > 0 do %>
          <section class="mb-4 rounded border border-yellow-200 bg-yellow-50 p-4">
            <h2 class="text-sm font-semibold text-yellow-900">BPF Restart Pending</h2>
            <div class="mt-2 flex flex-wrap gap-2 text-sm">
              <%= for sensor <- @restart_pending_sensors do %>
                <a href={"/sensors/#{sensor.id}"} class="rounded bg-yellow-100 px-2 py-1 text-yellow-900 hover:underline"><%= sensor.name %></a>
              <% end %>
            </div>
          </section>
        <% else %>
          <section class="mb-4 rounded border border-green-200 bg-green-50 p-4 text-sm font-medium text-green-900">
            No sensors have BPF restart pending.
          </section>
        <% end %>

        <section class="mb-4 rounded border border-gray-200 bg-white p-4">
          <div class="mb-3 flex items-center justify-between gap-3">
            <h2 class="text-lg font-semibold text-gray-900">Structured Rules</h2>
            <%= if can_manage_bpf?(@current_user) do %>
              <button type="button" phx-click="add_rule" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Add Rule</button>
            <% end %>
          </div>

          <%= if @rules == [] do %>
            <p class="text-sm text-gray-500">No structured rules.</p>
          <% else %>
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-gray-200 text-sm">
                <thead class="bg-gray-50 text-left text-xs font-medium uppercase text-gray-500">
                  <tr>
                    <th class="px-3 py-2">Order</th>
                    <th class="px-3 py-2">Type</th>
                    <th class="px-3 py-2">Label</th>
                    <th class="px-3 py-2">Parameters</th>
                    <th class="px-3 py-2">State</th>
                    <%= if can_manage_bpf?(@current_user) do %>
                      <th class="px-3 py-2 text-right">Actions</th>
                    <% end %>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 bg-white">
                  <%= for {rule, index} <- Enum.with_index(@rules) do %>
                    <tr>
                      <td class="px-3 py-2 text-gray-700"><%= index + 1 %></td>
                      <td class="px-3 py-2 font-medium text-gray-900"><%= rule_type_label(rule.rule_type) %></td>
                      <td class="px-3 py-2 text-gray-700"><%= Formatters.display(rule.label) %></td>
                      <td class="px-3 py-2 text-gray-700"><%= rule_summary(rule) %></td>
                      <td class="px-3 py-2">
                        <span class={if rule.enabled, do: "rounded bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800", else: "rounded bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700"}>
                          <%= if rule.enabled, do: "Enabled", else: "Disabled" %>
                        </span>
                      </td>
                      <%= if can_manage_bpf?(@current_user) do %>
                        <td class="px-3 py-2">
                          <div class="flex justify-end gap-2">
                            <button type="button" phx-click="reorder_rules" phx-value-index={index} phx-value-direction="up" class="rounded border border-gray-300 px-2 py-1 text-xs text-gray-700 disabled:text-gray-300" disabled={index == 0}>Up</button>
                            <button type="button" phx-click="reorder_rules" phx-value-index={index} phx-value-direction="down" class="rounded border border-gray-300 px-2 py-1 text-xs text-gray-700 disabled:text-gray-300" disabled={index == length(@rules) - 1}>Down</button>
                            <button type="button" phx-click="toggle_rule" phx-value-index={index} class="rounded border border-gray-300 px-2 py-1 text-xs text-gray-700">Toggle</button>
                            <button type="button" phx-click="edit_rule" phx-value-index={index} class="rounded border border-gray-300 px-2 py-1 text-xs text-gray-700">Edit</button>
                            <button type="button" phx-click="delete_rule" phx-value-index={index} class="rounded border border-red-300 px-2 py-1 text-xs text-red-700">Delete</button>
                          </div>
                        </td>
                      <% end %>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          <% end %>
        </section>

        <%= if @rule_form && can_manage_bpf?(@current_user) do %>
          <section class="mb-4 rounded border border-blue-200 bg-blue-50 p-4">
            <h2 class="mb-3 text-lg font-semibold text-gray-900"><%= if is_nil(@rule_form.index), do: "Add Rule", else: "Edit Rule" %></h2>
            <.form for={%{}} as={:rule} phx-submit="save_rule" class="grid gap-3 text-sm md:grid-cols-3">
              <input type="hidden" name="rule[index]" value={@rule_form.index} />
              <label>
                <span class="mb-1 block text-xs font-medium uppercase text-gray-600">Type</span>
                <select name="rule[rule_type]" class="w-full rounded border border-gray-300 px-3 py-2">
                  <option value="port_exclusion" selected={@rule_form.rule_type == "port_exclusion"}>Port Exclusion</option>
                  <option value="cidr_pair" selected={@rule_form.rule_type == "cidr_pair"}>CIDR Pair</option>
                  <option value="elephant_flow" selected={@rule_form.rule_type == "elephant_flow"}>Elephant Flow</option>
                </select>
              </label>
              <label>
                <span class="mb-1 block text-xs font-medium uppercase text-gray-600">Label</span>
                <input name="rule[label]" value={@rule_form.label} class="w-full rounded border border-gray-300 px-3 py-2" />
              </label>
              <label>
                <span class="mb-1 block text-xs font-medium uppercase text-gray-600">Protocol</span>
                <select name="rule[protocol]" class="w-full rounded border border-gray-300 px-3 py-2">
                  <option value="any" selected={@rule_form.protocol == "any"}>Any</option>
                  <option value="tcp" selected={@rule_form.protocol == "tcp"}>TCP</option>
                  <option value="udp" selected={@rule_form.protocol == "udp"}>UDP</option>
                </select>
              </label>
              <label>
                <span class="mb-1 block text-xs font-medium uppercase text-gray-600">Source CIDR</span>
                <input name="rule[src_cidr]" value={@rule_form.src_cidr} class="w-full rounded border border-gray-300 px-3 py-2" />
              </label>
              <label>
                <span class="mb-1 block text-xs font-medium uppercase text-gray-600">Destination CIDR</span>
                <input name="rule[dst_cidr]" value={@rule_form.dst_cidr} class="w-full rounded border border-gray-300 px-3 py-2" />
              </label>
              <div class="grid grid-cols-2 gap-2">
                <label>
                  <span class="mb-1 block text-xs font-medium uppercase text-gray-600">Port</span>
                  <input name="rule[port]" value={@rule_form.port} class="w-full rounded border border-gray-300 px-3 py-2" />
                </label>
                <label>
                  <span class="mb-1 block text-xs font-medium uppercase text-gray-600">Port End</span>
                  <input name="rule[port_end]" value={@rule_form.port_end} class="w-full rounded border border-gray-300 px-3 py-2" />
                </label>
              </div>
              <label class="flex items-center gap-2 md:col-span-3">
                <input type="hidden" name="rule[enabled]" value="false" />
                <input type="checkbox" name="rule[enabled]" value="true" checked={@rule_form.enabled} class="rounded border-gray-300" />
                <span class="text-sm font-medium text-gray-700">Enabled</span>
              </label>
              <%= for error <- @rule_form.errors do %>
                <p class="text-sm font-medium text-red-700 md:col-span-3"><%= error %></p>
              <% end %>
              <div class="flex gap-2 md:col-span-3">
                <button type="submit" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Save Rule</button>
                <button type="button" phx-click="cancel_rule" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700">Cancel</button>
              </div>
            </.form>
          </section>
        <% end %>

        <section class="mb-4 rounded border border-gray-200 bg-white p-4">
          <h2 class="mb-3 text-lg font-semibold text-gray-900">Raw BPF Expression</h2>
          <%= if can_manage_bpf?(@current_user) do %>
            <form phx-change="update_composition_mode" class="mb-3">
              <label class="block max-w-xs text-sm">
                <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Composition</span>
                <select name="composition_mode" class="w-full rounded border border-gray-300 px-3 py-2">
                  <option value="append" selected={@composition_mode == "append"}>Append</option>
                  <option value="replace" selected={@composition_mode == "replace"}>Replace</option>
                </select>
              </label>
            </form>
            <form phx-change="update_raw_expression">
              <textarea name="raw_expression" phx-debounce="300" rows="5" class="w-full rounded border border-gray-300 px-3 py-2 font-mono text-sm"><%= @raw_expression %></textarea>
            </form>
          <% else %>
            <dl class="grid gap-3 text-sm md:grid-cols-2">
              <.field label="Composition" value={String.capitalize(@composition_mode)} />
              <.field label="Raw Expression" value={raw_display(@raw_expression)} />
            </dl>
          <% end %>
        </section>

        <section class="mb-4 rounded border border-gray-200 bg-white p-4">
          <h2 class="mb-3 text-lg font-semibold text-gray-900">Compiled Expression Preview</h2>
          <%= if @composition_mode == "replace" && @rules != [] do %>
            <p class="mb-3 rounded border border-yellow-200 bg-yellow-50 px-3 py-2 text-sm text-yellow-900">Replace mode ignores structured rules.</p>
          <% end %>
          <%= if @compiled_expression == "" do %>
            <p class="mb-3 rounded border border-yellow-200 bg-yellow-50 px-3 py-2 text-sm text-yellow-900">No filter expression is configured.</p>
          <% end %>
          <pre class="min-h-24 overflow-x-auto rounded bg-gray-900 p-3 text-sm text-gray-50"><%= raw_display(@compiled_expression) %></pre>
          <%= if @validation_result do %>
            <p class={"mt-3 rounded border px-3 py-2 text-sm font-medium #{validation_class(@validation_result)}"}>
              <%= validation_message(@validation_result) %>
            </p>
          <% end %>
        </section>

        <%= if can_manage_bpf?(@current_user) do %>
          <section class="flex flex-wrap justify-end gap-2">
            <button type="button" phx-click="validate" phx-disable-with="Validating..." disabled={@validating} class="rounded border border-gray-300 px-4 py-2 text-sm font-medium text-gray-800 disabled:bg-gray-100">Validate</button>
            <button type="button" phx-click="reset" class="rounded border border-red-300 px-4 py-2 text-sm font-medium text-red-700">Reset</button>
            <button type="button" phx-click="save" phx-disable-with="Saving..." class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Save</button>
          </section>
        <% end %>

        <%= if @show_reset_confirm do %>
          <section class="mt-4 rounded border border-red-200 bg-red-50 p-4">
            <p class="text-sm font-medium text-red-900">Reset this BPF profile?</p>
            <div class="mt-3 flex gap-2">
              <button type="button" phx-click="confirm_reset" class="rounded bg-red-700 px-3 py-2 text-sm font-medium text-white">Confirm Reset</button>
              <button type="button" phx-click="cancel_reset" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800">Cancel</button>
            </div>
          </section>
        <% end %>
      <% end %>
    </main>
    """
  end
end
