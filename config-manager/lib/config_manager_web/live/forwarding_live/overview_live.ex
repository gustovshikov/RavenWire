defmodule ConfigManagerWeb.ForwardingLive.OverviewLive do
  @moduledoc "Pool-level Vector forwarding sink overview."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers

  alias ConfigManager.{Forwarding, Pools}
  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.{AuthHelpers, Formatters}

  @schema_modes [
    {"Raw", "raw"},
    {"Elastic Common Schema", "ecs"},
    {"OCSF", "ocsf"},
    {"Splunk CIM", "splunk_cim"}
  ]

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        if connected?(socket),
          do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}:forwarding")

        {:ok,
         socket
         |> assign(
           not_found: false,
           page_title: "#{pool.name} Forwarding",
           pool: pool,
           pending_delete_id: nil,
           testing_sink_ids: MapSet.new()
         )
         |> load_state()}
    end
  end

  @impl true
  def handle_info({:connection_test_result, sink_id, result}, socket) do
    message =
      Map.get(result, :message) || Map.get(result, "message") || "Connection test finished."

    {:noreply,
     socket
     |> assign(:testing_sink_ids, MapSet.delete(socket.assigns.testing_sink_ids, sink_id))
     |> put_flash(result_flash_kind(result), message)
     |> load_state()}
  end

  def handle_info(_message, socket), do: {:noreply, load_state(socket)}

  @impl true
  def handle_event("toggle_sink", %{"id" => sink_id}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:toggle_sink"),
         {:ok, _sink} <-
           Forwarding.toggle_sink(socket.assigns.pool.id, sink_id, socket.assigns.current_user) do
      {:noreply, socket |> put_flash(:info, "Forwarding sink state updated.") |> load_state()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, format_error(reason))}
    end
  end

  def handle_event("delete_sink", %{"id" => sink_id}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:delete_sink") do
      {:noreply, assign(socket, :pending_delete_id, sink_id)}
    else
      {:error, :forbidden} -> {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  def handle_event("cancel_delete", _params, socket) do
    {:noreply, assign(socket, :pending_delete_id, nil)}
  end

  def handle_event("confirm_delete", _params, %{assigns: %{pending_delete_id: nil}} = socket) do
    {:noreply, socket}
  end

  def handle_event("confirm_delete", _params, socket) do
    sink_id = socket.assigns.pending_delete_id

    with :ok <- AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:delete_sink"),
         {:ok, _sink} <-
           Forwarding.delete_sink(socket.assigns.pool.id, sink_id, socket.assigns.current_user) do
      {:noreply,
       socket
       |> assign(:pending_delete_id, nil)
       |> put_flash(:info, "Forwarding sink deleted.")
       |> load_state()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, reason} ->
        {:noreply,
         socket |> assign(:pending_delete_id, nil) |> put_flash(:error, format_error(reason))}
    end
  end

  def handle_event("test_connection", %{"id" => sink_id}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:test_connection"),
         :ok <-
           Forwarding.test_connection(socket.assigns.pool.id, sink_id, self(),
             actor: socket.assigns.current_user
           ) do
      {:noreply,
       assign(
         socket,
         :testing_sink_ids,
         MapSet.put(socket.assigns.testing_sink_ids, sink_id)
       )}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, :file_sink} ->
        {:noreply, put_flash(socket, :error, "File sinks do not support connection tests.")}

      {:error, :concurrent_limit} ->
        {:noreply, put_flash(socket, :error, "Too many connection tests are already running.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, format_error(reason))}
    end
  end

  def handle_event("update_schema_mode", %{"schema_mode" => schema_mode}, socket) do
    with :ok <-
           AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:update_schema_mode"),
         {:ok, _pool} <-
           Forwarding.update_schema_mode(
             socket.assigns.pool.id,
             schema_mode,
             socket.assigns.current_user
           ) do
      {:noreply, socket |> put_flash(:info, "Forwarding schema mode updated.") |> load_state()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, format_error(reason))}
    end
  end

  def handle_event("reveal_secret", _params, socket) do
    with :ok <- AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:reveal_secret") do
      {:noreply,
       put_flash(socket, :info, "Sink secrets are write-only. Edit the sink to rotate a secret.")}
    else
      {:error, :forbidden} -> {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
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
      <div class="mt-2 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900"><%= @pool.name %> Forwarding</h1>
          <p class="text-sm text-gray-500">Vector sink configuration saved with this pool and deployed explicitly.</p>
        </div>
        <%= if can_manage_forwarding?(@current_user) do %>
          <a href={"/pools/#{@pool.id}/forwarding/sinks/new"} class="w-fit rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Add Sink</a>
        <% end %>
      </div>

      <.pool_nav pool={@pool} />

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <dl class="grid gap-3 text-sm md:grid-cols-5">
          <.field label="Sinks" value={"#{@summary.enabled_count}/#{@summary.sink_count} enabled"} />
          <.field label="Schema Mode" value={schema_mode_label(@summary.schema_mode)} />
          <.field label="Forwarding Version" value={@summary.forwarding_config_version} />
          <.field label="Updated At" value={Formatters.format_utc(@summary.forwarding_config_updated_at)} />
          <.field label="Updated By" value={@summary.forwarding_config_updated_by} />
        </dl>
      </section>

      <section class="mb-4 rounded border border-blue-200 bg-blue-50 p-4">
        <p class="text-sm font-medium text-blue-950">Saved forwarding changes require an explicit deployment before sensors receive them.</p>
      </section>

      <section class="mb-4 rounded border border-gray-200 bg-white p-4">
        <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 class="text-lg font-semibold text-gray-900">Schema Mapping</h2>
            <p class="text-sm text-gray-600">Controls the event schema emitted by configured forwarding sinks.</p>
          </div>
          <form phx-change="update_schema_mode" class="w-full md:w-72">
            <label class="mb-1 block text-xs font-medium uppercase text-gray-600" for="schema-mode">Schema Mode</label>
            <select id="schema-mode" name="schema_mode" disabled={!can_manage_forwarding?(@current_user)} class="w-full rounded border border-gray-300 px-3 py-2 text-sm disabled:bg-gray-100">
              <%= for {label, value} <- @schema_modes do %>
                <option value={value} selected={@summary.schema_mode == value}><%= label %></option>
              <% end %>
            </select>
          </form>
        </div>
      </section>

      <section class="mb-4 rounded border border-gray-200 bg-white">
        <div class="border-b border-gray-200 px-4 py-3">
          <h2 class="text-lg font-semibold text-gray-900">Forwarding Sinks</h2>
        </div>

        <%= if @sinks == [] do %>
          <div class="p-6">
            <p class="text-sm text-gray-600">No forwarding sinks configured.</p>
          </div>
        <% else %>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 text-sm">
              <thead class="bg-gray-50 text-left text-xs font-medium uppercase text-gray-500">
                <tr>
                  <th class="px-4 py-3">Name</th>
                  <th class="px-4 py-3">Type</th>
                  <th class="px-4 py-3">Destination</th>
                  <th class="px-4 py-3">State</th>
                  <th class="px-4 py-3">Last Test</th>
                  <%= if can_manage_forwarding?(@current_user) do %>
                    <th class="px-4 py-3 text-right">Actions</th>
                  <% end %>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100 bg-white">
                <%= for sink <- @sinks do %>
                  <tr class={if sink.enabled, do: "", else: "bg-gray-50 text-gray-500"}>
                    <td class="px-4 py-3 font-medium text-gray-900"><%= sink.name %></td>
                    <td class="px-4 py-3"><%= sink_type_label(sink.sink_type) %></td>
                    <td class="max-w-sm break-words px-4 py-3"><%= sink_destination(sink) %></td>
                    <td class="px-4 py-3">
                      <span class={if sink.enabled, do: "rounded bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800", else: "rounded bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700"}>
                        <%= if sink.enabled, do: "Enabled", else: "Disabled" %>
                      </span>
                    </td>
                    <td class="px-4 py-3"><%= last_test_label(sink) %></td>
                    <%= if can_manage_forwarding?(@current_user) do %>
                      <td class="px-4 py-3">
                        <div class="flex flex-wrap justify-end gap-2">
                          <a href={"/pools/#{@pool.id}/forwarding/sinks/#{sink.id}/edit"} class="rounded border border-gray-300 px-2 py-1 text-xs font-medium text-gray-700">Edit</a>
                          <button type="button" phx-click="toggle_sink" phx-value-id={sink.id} class="rounded border border-gray-300 px-2 py-1 text-xs font-medium text-gray-700"><%= if sink.enabled, do: "Disable", else: "Enable" %></button>
                          <button type="button" phx-click="test_connection" phx-value-id={sink.id} disabled={sink.sink_type == "file" || MapSet.member?(@testing_sink_ids, sink.id)} class="rounded border border-gray-300 px-2 py-1 text-xs font-medium text-gray-700 disabled:bg-gray-100 disabled:text-gray-400"><%= if MapSet.member?(@testing_sink_ids, sink.id), do: "Testing", else: "Test" %></button>
                          <button type="button" phx-click="delete_sink" phx-value-id={sink.id} class="rounded border border-red-300 px-2 py-1 text-xs font-medium text-red-700">Delete</button>
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

      <section class="rounded border border-gray-200 bg-white p-4">
        <h2 class="text-lg font-semibold text-gray-900">Forwarding Telemetry</h2>
        <p class="mt-2 text-sm text-gray-600">Forwarding telemetry is not yet available. It requires a future HealthReport protobuf extension.</p>
      </section>

      <%= if @pending_delete_id do %>
        <section class="mt-4 rounded border border-red-200 bg-red-50 p-4">
          <p class="text-sm font-medium text-red-900">Delete this forwarding sink?</p>
          <div class="mt-3 flex gap-2">
            <button type="button" phx-click="confirm_delete" class="rounded bg-red-700 px-3 py-2 text-sm font-medium text-white">Confirm Delete</button>
            <button type="button" phx-click="cancel_delete" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800">Cancel</button>
          </div>
        </section>
      <% end %>
    </main>
    """
  end

  defp load_state(%{assigns: %{not_found: true}} = socket), do: socket

  defp load_state(socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)

    assign(socket,
      pool: pool,
      sinks: Forwarding.list_sinks(pool.id),
      summary: Forwarding.forwarding_summary(pool.id),
      schema_modes: @schema_modes
    )
  end

  defp can_manage_forwarding?(nil), do: false
  defp can_manage_forwarding?(user), do: Policy.has_permission?(user.role, "forwarding:manage")

  defp result_flash_kind(result) do
    if Map.get(result, :success) || Map.get(result, "success"), do: :info, else: :error
  end

  defp schema_mode_label("raw"), do: "Raw"
  defp schema_mode_label("ecs"), do: "Elastic Common Schema"
  defp schema_mode_label("ocsf"), do: "OCSF"
  defp schema_mode_label("splunk_cim"), do: "Splunk CIM"
  defp schema_mode_label(value), do: Formatters.display(value)

  defp sink_type_label("splunk_hec"), do: "Splunk HEC"
  defp sink_type_label("http"), do: "HTTP"
  defp sink_type_label("syslog"), do: "Syslog"
  defp sink_type_label("kafka"), do: "Kafka"
  defp sink_type_label("s3"), do: "S3"
  defp sink_type_label("file"), do: "File"
  defp sink_type_label(value), do: Formatters.display(value)

  defp sink_destination(sink) do
    config = config_map(sink)

    case sink.sink_type do
      "splunk_hec" -> Map.get(config, "endpoint")
      "http" -> Map.get(config, "endpoint")
      "syslog" -> "#{Map.get(config, "host")}:#{Map.get(config, "port")}"
      "kafka" -> Map.get(config, "bootstrap_servers")
      "s3" -> "#{Map.get(config, "bucket")} / #{Map.get(config, "region")}"
      "file" -> Map.get(config, "path_template")
      _type -> nil
    end
    |> Formatters.display()
  end

  defp last_test_label(%{last_test_result: nil}), do: "Not tested"

  defp last_test_label(sink) do
    case Jason.decode(sink.last_test_result || "") do
      {:ok, %{"success" => true}} -> "Success at #{Formatters.format_utc(sink.last_test_at)}"
      {:ok, %{"message" => message}} -> "Failed: #{message}"
      _error -> "Failed"
    end
  end

  defp config_map(sink) do
    case Jason.decode(sink.config || "") do
      {:ok, config} when is_map(config) -> config
      _error -> %{}
    end
  end

  defp format_error(%Ecto.Changeset{} = changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, _opts} -> message end)
    |> Enum.flat_map(fn {field, messages} ->
      Enum.map(messages, fn message -> "#{field} #{message}" end)
    end)
    |> Enum.join(", ")
  end

  defp format_error(reason), do: "Forwarding operation failed: #{inspect(reason)}"
end
