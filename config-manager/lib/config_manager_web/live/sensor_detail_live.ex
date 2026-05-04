defmodule ConfigManagerWeb.SensorDetailLive do
  @moduledoc "Read-only sensor detail page with real-time health updates."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.Formatters

  alias ConfigManager.{Audit, Pools, Repo, SensorAgentClient, SensorPod}
  alias ConfigManager.Auth.Policy
  alias ConfigManager.Health.Registry

  @expected_containers [
    {"zeek", ["zeek", "systemd-zeek"]},
    {"suricata", ["suricata", "systemd-suricata"]},
    {"vector", ["vector", "systemd-vector"]},
    {"pcap_ring_writer", ["pcap_ring_writer", "pcap-ring-writer", "systemd-pcap-ring-writer"]}
  ]
  @action_permissions %{
    "validate_config" => "sensor:operate",
    "reload_zeek" => "sensor:operate",
    "reload_suricata" => "sensor:operate",
    "restart_vector" => "sensor:operate",
    "support_bundle" => "bundle:download",
    "revoke" => "enrollment:manage"
  }
  @action_labels %{
    "validate_config" => "Validate Config",
    "reload_zeek" => "Reload Zeek",
    "reload_suricata" => "Reload Suricata",
    "restart_vector" => "Restart Vector",
    "support_bundle" => "Generate Support Bundle",
    "revoke" => "Revoke Sensor"
  }
  @action_audit_names %{
    "validate_config" => "sensor_validate_config",
    "reload_zeek" => "sensor_reload_zeek",
    "reload_suricata" => "sensor_reload_suricata",
    "restart_vector" => "sensor_restart_vector",
    "support_bundle" => "sensor_support_bundle_generate",
    "revoke" => "sensor_revoke"
  }

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Repo.get(SensorPod, id) do
      nil ->
        {:ok,
         socket
         |> assign(:page_title, "Sensor Not Found")
         |> assign(:not_found, true)}

      %SensorPod{} = pod ->
        health_key = pod.name

        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, Registry.pod_topic(health_key))
        end

        {:ok,
         socket
         |> assign(:page_title, "Sensor #{pod.name}")
         |> assign(:not_found, false)
         |> assign(:pod, pod)
         |> assign(:pool_name, Pools.pool_name(pod.pool_id))
         |> assign(:health_key, health_key)
         |> assign(:health, Registry.get(health_key))
         |> assign(:degradation_reasons, Registry.get_degradation_reasons(health_key))
         |> assign(:in_flight_actions, MapSet.new())
         |> assign(:confirm_revoke, false)
         |> assign(:stale_threshold_sec, stale_threshold_sec())
         |> assign(:action_timeout_ms, action_timeout_ms())}
    end
  end

  @impl true
  def handle_info({:pod_updated, health_key}, %{assigns: %{health_key: health_key}} = socket) do
    {:noreply,
     socket
     |> assign(:health, Registry.get(health_key))
     |> assign(:degradation_reasons, Registry.get_degradation_reasons(health_key))}
  end

  def handle_info(
        {:pod_degraded, health_key, reason, _value},
        %{assigns: %{health_key: health_key}} = socket
      ) do
    reasons = socket.assigns.degradation_reasons
    reasons = if reason in reasons, do: reasons, else: [reason | reasons]
    {:noreply, assign(socket, :degradation_reasons, reasons)}
  end

  def handle_info(
        {:pod_recovered, health_key, reason},
        %{assigns: %{health_key: health_key}} = socket
      ) do
    {:noreply,
     assign(socket, :degradation_reasons, List.delete(socket.assigns.degradation_reasons, reason))}
  end

  def handle_info(
        {:pool_assignment_changed, sensor_id, _pool_id},
        %{assigns: %{pod: %{id: sensor_id}}} = socket
      ) do
    pod = Repo.get!(SensorPod, sensor_id)
    {:noreply, assign(socket, pod: pod, pool_name: Pools.pool_name(pod.pool_id))}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def handle_event("action", %{"action" => "revoke"}, socket) do
    if permitted?(socket.assigns.current_user, "revoke") do
      {:noreply, assign(socket, :confirm_revoke, true)}
    else
      {:noreply, deny_action(socket, "revoke")}
    end
  end

  def handle_event("cancel_revoke", _params, socket),
    do: {:noreply, assign(socket, :confirm_revoke, false)}

  def handle_event("confirm_revoke", _params, socket) do
    if permitted?(socket.assigns.current_user, "revoke") do
      case ConfigManager.CA.Revocation.revoke_pod(socket.assigns.pod.id, :operator_requested) do
        :ok ->
          pod = Repo.get!(SensorPod, socket.assigns.pod.id)
          log_action(socket, "revoke", "success", %{})

          {:noreply,
           socket
           |> assign(:pod, pod)
           |> assign(:confirm_revoke, false)
           |> put_flash(:info, "Sensor revoked.")}

        {:error, reason} ->
          log_action(socket, "revoke", "failure", %{reason: inspect(reason)})

          {:noreply,
           socket
           |> assign(:confirm_revoke, false)
           |> put_flash(:error, "Revoke Sensor failed: #{format_reason(reason)}")}
      end
    else
      {:noreply, deny_action(socket, "revoke")}
    end
  end

  def handle_event("action", %{"action" => action}, socket) do
    cond do
      not Map.has_key?(@action_permissions, action) ->
        {:noreply, put_flash(socket, :error, "Unknown sensor action.")}

      not permitted?(socket.assigns.current_user, action) ->
        {:noreply, deny_action(socket, action)}

      control_action?(action) and no_control_api?(socket.assigns.pod) ->
        {:noreply, put_flash(socket, :error, "Sensor agent is not reachable.")}

      true ->
        result =
          case action do
            "validate_config" -> SensorAgentClient.validate_config(socket.assigns.pod)
            "reload_zeek" -> SensorAgentClient.reload_zeek(socket.assigns.pod)
            "reload_suricata" -> SensorAgentClient.reload_suricata(socket.assigns.pod)
            "restart_vector" -> SensorAgentClient.restart_vector(socket.assigns.pod)
            "support_bundle" -> SensorAgentClient.request_support_bundle(socket.assigns.pod)
          end

        socket =
          case result do
            {:ok, detail} ->
              log_action(socket, action, "success", sanitize_detail(detail))
              put_flash(socket, :info, "#{@action_labels[action]} completed.")

            {:error, reason} ->
              log_action(socket, action, "failure", %{reason: format_reason(reason)})

              put_flash(
                socket,
                :error,
                "#{@action_labels[action]} failed: #{format_reason(reason)}"
              )
          end

        {:noreply, socket}
    end
  end

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-12">
      <a href="/" class="text-sm text-blue-600 hover:underline">Back to dashboard</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">Sensor Not Found</h1>
      <p class="mt-2 text-gray-600">The requested sensor was not found.</p>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 border-b border-gray-200 pb-4 md:flex-row md:items-center md:justify-between">
        <div>
          <a href="/" class="text-sm text-blue-600 hover:underline">Back to dashboard</a>
          <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pod.name %></h1>
          <p class="text-sm text-gray-500">Sensor detail and live health state</p>
        </div>
        <span class={"inline-flex w-fit items-center rounded px-2.5 py-1 text-xs font-medium #{status_class(@pod.status)}"}>
          Status: <%= @pod.status %>
        </span>
      </div>

      <.status_banners pod={@pod} health={@health} stale_threshold_sec={@stale_threshold_sec} />
      <.degradation_summary reasons={@degradation_reasons} />
      <.identity_section pod={@pod} health={@health} />
      <.host_readiness_section health={@health} />
      <.container_section health={@health} />
      <.capture_section health={@health} />
      <.storage_section pod={@pod} health={@health} />
      <.clock_section health={@health} degradation_reasons={@degradation_reasons} />
      <.forwarding_section />
      <.actions_section
        pod={@pod}
        current_user={@current_user}
        in_flight_actions={@in_flight_actions}
        confirm_revoke={@confirm_revoke}
      />
    </main>
    """
  end

  attr(:pod, :map, required: true)
  attr(:health, :any, required: true)
  attr(:stale_threshold_sec, :integer, required: true)

  def status_banners(assigns) do
    ~H"""
    <div class="mb-4 space-y-2">
      <%= cond do %>
        <% @pod.status == "revoked" -> %>
          <div class="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">Revoked sensor: operational actions are hidden.</div>
        <% @pod.status == "pending" -> %>
          <div class="rounded border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-900">Pending enrollment: Control API actions are disabled until enrollment completes.</div>
        <% true -> %>
      <% end %>

      <%= cond do %>
        <% is_nil(@health) -> %>
          <div class="rounded border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-700">This sensor is not currently reporting health data.</div>
        <% stale_health?(@health, @stale_threshold_sec) -> %>
          <div class="rounded border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-900">
            Stale health data: last report <%= @health.timestamp_unix_ms |> report_datetime() |> format_relative_age() %>.
          </div>
        <% true -> %>
      <% end %>
    </div>
    """
  end

  attr(:reasons, :list, required: true)

  def degradation_summary(assigns) do
    ~H"""
    <%= if @reasons != [] do %>
      <section aria-label="Degradation Summary" class="mb-4 rounded border border-orange-200 bg-orange-50 px-4 py-3">
        <h2 class="text-sm font-semibold text-orange-900">Degradation Summary</h2>
        <ul class="mt-2 list-disc space-y-1 pl-5 text-sm text-orange-900">
          <%= for reason <- Enum.sort(@reasons) do %>
            <li><%= reason_label(reason) %></li>
          <% end %>
        </ul>
      </section>
    <% end %>
    """
  end

  attr(:pod, :map, required: true)
  attr(:health, :any, required: true)

  def identity_section(assigns) do
    ~H"""
    <section aria-label="Sensor Identity" class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Identity</h2>
      <dl class="grid gap-3 text-sm md:grid-cols-2 lg:grid-cols-4">
        <.field label="Name" value={@pod.name} />
        <.field label="UUID" value={@pod.id} mono />
        <div>
          <dt class="text-xs font-medium uppercase text-gray-500">Pool</dt>
          <dd class="mt-1 break-words text-gray-900">
            <%= if @pod.pool_id do %>
              <a href={"/pools/#{@pod.pool_id}"} class="text-blue-700 hover:underline"><%= display(@pool_name || @pod.pool_id) %></a>
            <% else %>
              <%= display(nil) %>
            <% end %>
          </dd>
        </div>
        <.field label="Status" value={@pod.status} />
        <.field label="Cert Serial" value={@pod.cert_serial} mono />
        <div>
          <dt class="text-xs font-medium uppercase text-gray-500">Cert Expires</dt>
          <dd class={"mt-1 font-medium #{cert_class(@pod.cert_expires_at)}"}>
            <%= format_utc(@pod.cert_expires_at) %>
            <span class="block text-xs"><%= cert_label(@pod.cert_expires_at) %></span>
          </dd>
        </div>
        <.field label="Enrolled At" value={format_utc(@pod.enrolled_at)} />
        <.field label="Enrolled By" value={@pod.enrolled_by} />
        <div>
          <dt class="text-xs font-medium uppercase text-gray-500">Last Seen</dt>
          <dd class="mt-1 text-gray-900">
            <%= format_utc(@pod.last_seen_at) %>
            <span class="block text-xs text-gray-500"><%= format_relative_age(@pod.last_seen_at) %></span>
          </dd>
        </div>
        <.field label="Control API Host" value={@pod.control_api_host} mono />
        <.field label="Latest Health Report" value={format_utc_from_unix_ms(if @health, do: @health.timestamp_unix_ms, else: nil)} />
      </dl>
    </section>
    """
  end

  attr(:health, :any, required: true)

  def host_readiness_section(assigns) do
    ~H"""
    <section aria-label="Host Readiness" class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Host Readiness</h2>
      <%= if @health && @health.system do %>
        <dl class="grid gap-3 text-sm md:grid-cols-2 lg:grid-cols-4">
          <.field label="Kernel" value={@health.system.kernel_release} />
          <.field label="Capture Interface" value={@health.system.capture_interface} mono />
          <.field label="NIC Driver" value={@health.system.nic_driver} />
          <.field label="AF_PACKET" value={if @health.system.af_packet_available, do: "available", else: "unavailable"} />
          <.field label="Host Uptime" value={format_uptime(@health.system.uptime_seconds)} />
          <.field label="CPU" value={format_percent(@health.system.cpu_percent)} />
          <.field label="RAM Used" value={"#{format_percent(@health.system.memory_used_percent)} (#{format_bytes(@health.system.memory_used_bytes)} / #{format_bytes(@health.system.memory_total_bytes)})"} />
          <.field label="Disk" value={"#{display(@health.system.disk_path)} #{format_percent(@health.system.disk_used_percent)}"} />
        </dl>
      <% else %>
        <p class="text-sm text-gray-600">Host readiness data is not yet available from the Sensor Agent.</p>
      <% end %>
    </section>
    """
  end

  attr(:health, :any, required: true)

  def container_section(assigns) do
    assigns = assign(assigns, :containers, expected_containers(assigns.health))

    ~H"""
    <section aria-label="Container Health" class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Containers</h2>
      <%= if @containers == [] do %>
        <p class="text-sm text-gray-600">No container data is available.</p>
      <% else %>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-xs uppercase text-gray-500">
                <th class="py-2 pr-4 font-medium">Name</th>
                <th class="py-2 pr-4 font-medium">State</th>
                <th class="py-2 pr-4 font-medium">Uptime</th>
                <th class="py-2 pr-4 font-medium">CPU</th>
                <th class="py-2 font-medium">Memory</th>
              </tr>
            </thead>
            <tbody>
              <%= for container <- @containers do %>
                <tr class="border-b border-gray-100 last:border-0">
                  <th class="py-2 pr-4 font-mono font-medium text-gray-900"><%= container.name %></th>
                  <td class="py-2 pr-4">
                    <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{status_class(container.state)}"}>
                      <%= container.state %>
                    </span>
                  </td>
                  <td class="py-2 pr-4 text-gray-700"><%= format_uptime(container.uptime_seconds) %></td>
                  <td class={"py-2 pr-4 #{if container.cpu_percent && container.cpu_percent > 90, do: "font-semibold text-yellow-800", else: "text-gray-700"}"}>
                    <%= format_percent(container.cpu_percent) %>
                    <%= if container.cpu_percent && container.cpu_percent > 90, do: "(warning)" %>
                  </td>
                  <td class="py-2 text-gray-700"><%= format_bytes(container.memory_bytes) %></td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      <% end %>
    </section>
    """
  end

  attr(:health, :any, required: true)

  def capture_section(assigns) do
    assigns = assign(assigns, :consumers, capture_consumers(assigns.health))

    ~H"""
    <section aria-label="Capture Pipeline" class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Capture Pipeline</h2>
      <%= if @consumers == [] do %>
        <p class="text-sm text-gray-600">No capture data is available.</p>
      <% else %>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-xs uppercase text-gray-500">
                <th class="py-2 pr-4 font-medium">Consumer</th>
                <th class="py-2 pr-4 font-medium">Packets Received</th>
                <th class="py-2 pr-4 font-medium">Packets Dropped</th>
                <th class="py-2 pr-4 font-medium">Drop</th>
                <th class="py-2 pr-4 font-medium">Throughput</th>
                <th class="py-2 font-medium">BPF Restart</th>
              </tr>
            </thead>
            <tbody>
              <%= for {name, stats} <- @consumers do %>
                <tr class="border-b border-gray-100 last:border-0">
                  <th class="py-2 pr-4 font-mono font-medium text-gray-900"><%= name %></th>
                  <td class="py-2 pr-4 text-gray-700"><%= stats.packets_received %></td>
                  <td class="py-2 pr-4 text-gray-700"><%= stats.packets_dropped %></td>
                  <td class={"py-2 pr-4 #{if stats.drop_percent > 5.0, do: "font-semibold text-red-700", else: "text-gray-700"}"}>
                    <%= format_percent(stats.drop_percent, 2) %>
                    <%= if stats.drop_percent > 5.0, do: "(critical)" %>
                  </td>
                  <td class="py-2 pr-4 text-gray-700"><%= format_throughput(stats.throughput_bps) %></td>
                  <td class="py-2">
                    <%= if stats.bpf_restart_pending do %>
                      <span class="inline-flex rounded bg-orange-100 px-2 py-0.5 text-xs font-medium text-orange-900">restart required</span>
                    <% else %>
                      <span class="text-gray-500">No</span>
                    <% end %>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      <% end %>
    </section>
    """
  end

  attr(:pod, :map, required: true)
  attr(:health, :any, required: true)

  def storage_section(assigns) do
    ~H"""
    <section aria-label="Storage" class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Storage</h2>
      <%= if @health && @health.storage do %>
        <dl class="mb-4 grid gap-3 text-sm md:grid-cols-2 lg:grid-cols-5">
          <.field label="PCAP Path" value={@health.storage.path} mono />
          <.field label="Total" value={format_bytes(@health.storage.total_bytes)} />
          <.field label="Used" value={format_bytes(@health.storage.used_bytes)} />
          <.field label="Available" value={format_bytes(@health.storage.available_bytes)} />
          <div>
            <dt class="text-xs font-medium uppercase text-gray-500">Used</dt>
            <dd class={"mt-1 font-medium #{storage_class(@health.storage.used_percent)}"}>
              <%= format_percent(@health.storage.used_percent) %>
              <%= storage_label(@health.storage.used_percent) %>
            </dd>
          </div>
        </dl>
      <% else %>
        <p class="mb-4 text-sm text-gray-600">No storage data is available.</p>
      <% end %>
      <h3 class="mb-2 text-sm font-semibold text-gray-700">PCAP Configuration</h3>
      <dl class="grid gap-3 text-sm md:grid-cols-4">
        <.field label="Ring Size" value={"#{@pod.pcap_ring_size_mb} MB"} />
        <.field label="Pre-alert Window" value={"#{@pod.pre_alert_window_sec}s"} />
        <.field label="Post-alert Window" value={"#{@pod.post_alert_window_sec}s"} />
        <.field label="Severity Threshold" value={@pod.alert_severity_threshold} />
      </dl>
    </section>
    """
  end

  attr(:health, :any, required: true)
  attr(:degradation_reasons, :list, required: true)

  def clock_section(assigns) do
    ~H"""
    <section aria-label="Clock" class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Clock</h2>
      <%= if @health && @health.clock do %>
        <dl class="grid gap-3 text-sm md:grid-cols-3">
          <div>
            <dt class="text-xs font-medium uppercase text-gray-500">Offset</dt>
            <dd class={"mt-1 font-medium #{if :clock_drift in @degradation_reasons, do: "text-red-700", else: "text-gray-900"}"}>
              <%= @health.clock.offset_ms %> ms
              <%= if :clock_drift in @degradation_reasons, do: "(degraded)" %>
            </dd>
          </div>
          <div>
            <dt class="text-xs font-medium uppercase text-gray-500">NTP Sync</dt>
            <dd class={"mt-1 font-medium #{if @health.clock.synchronized, do: "text-green-800", else: "text-yellow-800"}"}>
              <%= if @health.clock.synchronized, do: "Yes", else: "No (warning)" %>
            </dd>
          </div>
          <.field label="Source" value={@health.clock.source} mono />
        </dl>
      <% else %>
        <p class="text-sm text-gray-600">Clock data is not available.</p>
      <% end %>
    </section>
    """
  end

  def forwarding_section(assigns) do
    ~H"""
    <section aria-label="Forwarding" class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Forwarding</h2>
      <p class="text-sm text-gray-600">Forwarding data is not yet available from the Sensor Agent.</p>
    </section>
    """
  end

  attr(:pod, :map, required: true)
  attr(:current_user, :map, required: true)
  attr(:in_flight_actions, :any, required: true)
  attr(:confirm_revoke, :boolean, required: true)

  def actions_section(assigns) do
    assigns =
      assigns
      |> assign(:actions, visible_actions(assigns.current_user))
      |> assign(:action_labels, @action_labels)

    ~H"""
    <%= if @pod.status != "revoked" do %>
      <section aria-label="Sensor Actions" class="mb-4 rounded border border-gray-200 bg-white p-4">
        <h2 class="mb-3 text-lg font-semibold text-gray-900">Actions</h2>
        <%= if no_control_api?(@pod) do %>
          <p class="mb-3 text-sm text-yellow-800">Sensor agent is not reachable because no Control API host is configured.</p>
        <% end %>
        <div class="flex flex-wrap gap-2">
          <%= for action <- @actions do %>
            <%= if action == "revoke" or @pod.status != "pending" do %>
              <button
                type="button"
                phx-click="action"
                phx-value-action={action}
                aria-label={@action_labels[action]}
                disabled={(control_action?(action) and no_control_api?(@pod)) or MapSet.member?(@in_flight_actions, action)}
                class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-400 hover:bg-gray-50"
              >
                <%= @action_labels[action] %>
              </button>
            <% end %>
          <% end %>
        </div>
        <%= if @confirm_revoke do %>
          <div class="mt-4 rounded border border-red-200 bg-red-50 p-3">
            <p class="text-sm font-medium text-red-900">Confirm sensor revocation for <%= @pod.name %>?</p>
            <div class="mt-3 flex gap-2">
              <button type="button" phx-click="confirm_revoke" class="rounded bg-red-700 px-3 py-2 text-sm font-medium text-white">Confirm Revoke</button>
              <button type="button" phx-click="cancel_revoke" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800">Cancel</button>
            </div>
          </div>
        <% end %>
      </section>
    <% end %>
    """
  end

  attr(:label, :string, required: true)
  attr(:value, :any, required: true)
  attr(:mono, :boolean, default: false)

  def field(assigns) do
    ~H"""
    <div>
      <dt class="text-xs font-medium uppercase text-gray-500"><%= @label %></dt>
      <dd class={"mt-1 break-words text-gray-900 #{if @mono, do: "font-mono", else: ""}"}><%= display(@value) %></dd>
    </div>
    """
  end

  defp expected_containers(nil), do: []

  defp expected_containers(%{containers: containers}) when containers in [nil, []], do: []

  defp expected_containers(%{containers: containers}) do
    containers = containers || []
    by_name = Map.new(containers, &{&1.name, &1})
    expected_names = Enum.flat_map(@expected_containers, fn {_canonical, aliases} -> aliases end)

    expected =
      Enum.map(@expected_containers, fn {canonical, aliases} ->
        aliases
        |> Enum.find_value(&Map.get(by_name, &1))
        |> case do
          nil -> missing_container(canonical)
          container -> container
        end
      end)

    optional =
      containers
      |> Enum.reject(&(&1.name in expected_names))
      |> Enum.sort_by(& &1.name)

    expected ++ optional
  end

  defp missing_container(name),
    do: %{name: name, state: "missing", uptime_seconds: nil, cpu_percent: nil, memory_bytes: nil}

  defp capture_consumers(nil), do: []
  defp capture_consumers(%{capture: nil}), do: []

  defp capture_consumers(%{capture: %{consumers: consumers}}) when is_map(consumers) do
    consumers
    |> Enum.sort_by(fn {name, _stats} -> name end)
    |> Enum.map(fn {name, stats} ->
      {name, %{stats | throughput_bps: max(stats.throughput_bps || 0, 0)}}
    end)
  end

  defp capture_consumers(_), do: []

  defp visible_actions(nil), do: []

  defp visible_actions(user) do
    @action_permissions
    |> Enum.filter(fn {_action, permission} -> Policy.has_permission?(user.role, permission) end)
    |> Enum.map(fn {action, _permission} -> action end)
    |> Enum.sort_by(&Map.fetch!(@action_labels, &1))
  end

  defp permitted?(nil, _action), do: false

  defp permitted?(user, action) do
    permission = Map.fetch!(@action_permissions, action)
    Policy.has_permission?(user.role, permission)
  end

  defp control_action?("revoke"), do: false
  defp control_action?(_action), do: true

  defp no_control_api?(%{control_api_host: host}), do: is_nil(host) or host == ""

  defp deny_action(socket, action) do
    Audit.log(%{
      actor: socket.assigns.current_user.username,
      actor_type: "user",
      action: "permission_denied",
      target_type: "sensor_pod",
      target_id: socket.assigns.pod.id,
      result: "failure",
      detail: %{required_permission: @action_permissions[action], action: action}
    })

    put_flash(socket, :error, "Insufficient permissions.")
  end

  defp log_action(socket, action, result, detail) do
    Audit.log(%{
      actor: socket.assigns.current_user.username,
      actor_type: "user",
      action: @action_audit_names[action],
      target_type: "sensor_pod",
      target_id: socket.assigns.pod.id,
      result: result,
      detail: Map.put(detail, :required_permission, @action_permissions[action])
    })
  end

  defp sanitize_detail(detail) when is_map(detail) do
    Map.drop(detail, [
      "token",
      "secret",
      "password",
      "cert_pem",
      "private_key",
      :token,
      :secret,
      :password,
      :cert_pem,
      :private_key
    ])
  end

  defp sanitize_detail(_detail), do: %{}

  defp status_class("running"), do: "bg-green-100 text-green-800"
  defp status_class("enrolled"), do: "bg-green-100 text-green-800"
  defp status_class("pending"), do: "bg-yellow-100 text-yellow-900"
  defp status_class("restarting"), do: "bg-yellow-100 text-yellow-900"
  defp status_class("error"), do: "bg-red-100 text-red-800"
  defp status_class("revoked"), do: "bg-red-100 text-red-800"
  defp status_class("missing"), do: "bg-red-100 text-red-800"
  defp status_class("stopped"), do: "bg-gray-100 text-gray-700"
  defp status_class(_), do: "bg-gray-100 text-gray-700"

  defp cert_class(expires_at) do
    case cert_status(expires_at) do
      :expired -> "text-red-700"
      :expiring_soon -> "text-yellow-800"
      _ -> "text-gray-900"
    end
  end

  defp cert_label(expires_at) do
    case cert_status(expires_at) do
      :expired -> "expired"
      :expiring_soon -> "expiring soon"
      :valid -> "valid"
      :unknown -> "unknown"
    end
  end

  defp storage_class(percent) when is_number(percent) and percent > 95, do: "text-red-700"
  defp storage_class(percent) when is_number(percent) and percent > 85, do: "text-yellow-800"
  defp storage_class(_), do: "text-gray-900"

  defp storage_label(percent) when is_number(percent) and percent > 95, do: "(critical)"
  defp storage_label(percent) when is_number(percent) and percent > 85, do: "(warning)"
  defp storage_label(_), do: ""

  defp reason_label(:clock_drift), do: "Clock drift exceeds configured threshold"
  defp reason_label(:bpf_restart_pending), do: "BPF restart pending"
  defp reason_label(reason), do: reason |> to_string() |> String.replace("_", " ")

  defp stale_health?(nil, _threshold), do: false

  defp stale_health?(health, threshold) do
    case report_datetime(health.timestamp_unix_ms) do
      nil -> false
      datetime -> DateTime.diff(DateTime.utc_now(), datetime, :second) > threshold
    end
  end

  defp report_datetime(unix_ms) when is_integer(unix_ms) and unix_ms > 0 do
    case DateTime.from_unix(unix_ms, :millisecond) do
      {:ok, datetime} -> datetime
      {:error, _reason} -> nil
    end
  end

  defp report_datetime(_), do: nil

  defp format_reason(:no_control_api_host), do: "no Control API host configured"
  defp format_reason({:http_error, status, _body}), do: "HTTP #{status}"
  defp format_reason(reason), do: inspect(reason)

  defp stale_threshold_sec do
    :config_manager
    |> Application.get_env(:sensor_detail_stale_threshold_sec, 60)
    |> max(1)
  end

  defp action_timeout_ms do
    :config_manager
    |> Application.get_env(:sensor_detail_action_timeout_ms, 30_000)
    |> max(1_000)
  end
end
