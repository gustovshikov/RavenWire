defmodule ConfigManagerWeb.ForwardingLive.SinkFormLive do
  @moduledoc "Create and edit pool-level Vector forwarding sinks."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers

  alias ConfigManager.Forwarding
  alias ConfigManager.Forwarding.{ForwardingSink, SinkConfigSchema}
  alias ConfigManager.Pools
  alias ConfigManagerWeb.{AuthHelpers, Formatters}

  @sink_types [
    {"Splunk HEC", "splunk_hec"},
    {"HTTP", "http"},
    {"Syslog", "syslog"},
    {"Kafka", "kafka"},
    {"S3", "s3"},
    {"File", "file"}
  ]

  @impl true
  def mount(%{"id" => pool_id} = params, _session, socket) do
    case {socket.assigns.live_action, Pools.get_pool(pool_id)} do
      {_action, nil} ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      {:new, pool} ->
        {:ok,
         assign(socket,
           not_found: false,
           mode: :new,
           page_title: "#{pool.name} New Forwarding Sink",
           pool: pool,
           sink: nil,
           params: default_params("file"),
           errors: [],
           sink_types: @sink_types,
           testing?: false
         )}

      {:edit, pool} ->
        case Forwarding.get_sink_for_pool(pool.id, params["sink_id"]) do
          {:ok, sink} ->
            {:ok,
             assign(socket,
               not_found: false,
               mode: :edit,
               page_title: "#{pool.name} Edit Forwarding Sink",
               pool: pool,
               sink: sink,
               params: params_from_sink(sink),
               errors: [],
               sink_types: @sink_types,
               testing?: false
             )}

          {:error, :not_found} ->
            {:ok, assign(socket, not_found: true, page_title: "Sink Not Found")}
        end
    end
  end

  @impl true
  def handle_info({:connection_test_result, _sink_id, result}, socket) do
    message =
      Map.get(result, :message) || Map.get(result, "message") || "Connection test finished."

    {:noreply,
     socket
     |> assign(:testing?, false)
     |> put_flash(result_flash_kind(result), message)}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def handle_event("select_type", %{"sink" => params}, socket) do
    params = params |> merge_defaults() |> preserve_name(socket.assigns.params)
    {:noreply, assign(socket, params: params, errors: validate_params(params, socket))}
  end

  def handle_event("validate", %{"sink" => params}, socket) do
    params = merge_current_params(socket, params)
    {:noreply, assign(socket, params: params, errors: validate_params(params, socket))}
  end

  def handle_event("save", %{"sink" => params}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:save_sink") do
      save_sink(socket, merge_current_params(socket, params))
    else
      {:error, :forbidden} -> {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  def handle_event("test_connection", _params, %{assigns: %{mode: :edit}} = socket) do
    with :ok <- AuthHelpers.authorize(socket, "forwarding:manage", "forwarding:test_connection"),
         :ok <-
           Forwarding.test_connection(socket.assigns.pool.id, socket.assigns.sink.id, self(),
             actor: socket.assigns.current_user
           ) do
      {:noreply,
       socket |> assign(:testing?, true) |> put_flash(:info, "Connection test started.")}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, :file_sink} ->
        {:noreply, put_flash(socket, :error, "File sinks do not support connection tests.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, format_error(reason))}
    end
  end

  def handle_event("test_connection", _params, socket), do: {:noreply, socket}

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-10">
      <a href="/pools" class="text-sm text-blue-600 hover:underline">Back to pools</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900"><%= @page_title %></h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-5xl px-6 py-6">
      <a href={"/pools/#{@pool.id}/forwarding"} class="text-sm text-blue-600 hover:underline">Back to forwarding</a>
      <div class="mt-2">
        <h1 class="text-2xl font-bold text-gray-900"><%= if @mode == :new, do: "Add Forwarding Sink", else: "Edit Forwarding Sink" %></h1>
        <p class="text-sm text-gray-500"><%= @pool.name %> forwarding configuration</p>
      </div>

      <.pool_nav pool={@pool} />

      <%= if @errors != [] do %>
        <section class="mb-4 rounded border border-red-200 bg-red-50 p-4">
          <h2 class="text-sm font-semibold text-red-900">Fix the sink configuration</h2>
          <ul class="mt-2 list-disc pl-5 text-sm text-red-800">
            <%= for error <- @errors do %>
              <li><%= error %></li>
            <% end %>
          </ul>
        </section>
      <% end %>

      <.form for={%{}} as={:sink} phx-change="validate" phx-submit="save" class="space-y-5 rounded border border-gray-200 bg-white p-6">
        <section class="grid gap-4 md:grid-cols-3">
          <.text_field params={@params} field="name" label="Name" required />
          <div>
            <label class="mb-1 block text-sm font-medium text-gray-700" for="sink-type">Sink Type</label>
            <select id="sink-type" name="sink[sink_type]" phx-change="select_type" disabled={@mode == :edit} class="w-full rounded border border-gray-300 px-3 py-2 text-sm disabled:bg-gray-100">
              <%= for {label, value} <- @sink_types do %>
                <option value={value} selected={@params["sink_type"] == value}><%= label %></option>
              <% end %>
            </select>
            <%= if @mode == :edit do %>
              <input type="hidden" name="sink[sink_type]" value={@params["sink_type"]} />
            <% end %>
          </div>
          <.checkbox_field params={@params} field="enabled" label="Enabled" />
        </section>

        <section class="border-t border-gray-200 pt-5">
          <h2 class="mb-4 text-lg font-semibold text-gray-900"><%= sink_type_label(@params["sink_type"]) %> Settings</h2>
          <.type_fields params={@params} />
        </section>

        <section class="flex flex-wrap justify-end gap-2 border-t border-gray-200 pt-5">
          <%= if @mode == :edit do %>
            <button type="button" phx-click="test_connection" disabled={@params["sink_type"] == "file" || @testing?} class="rounded border border-gray-300 px-4 py-2 text-sm font-medium text-gray-800 disabled:bg-gray-100 disabled:text-gray-400"><%= if @testing?, do: "Testing", else: "Test Connection" %></button>
          <% end %>
          <a href={"/pools/#{@pool.id}/forwarding"} class="rounded border border-gray-300 px-4 py-2 text-sm font-medium text-gray-800">Cancel</a>
          <button type="submit" class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"><%= if @mode == :new, do: "Create Sink", else: "Save Sink" %></button>
        </section>
      </.form>
    </main>
    """
  end

  attr(:params, :map, required: true)

  def type_fields(%{params: %{"sink_type" => "splunk_hec"}} = assigns) do
    ~H"""
    <div class="grid gap-4 md:grid-cols-2">
      <.text_field params={@params} field="endpoint" label="HEC Endpoint" required />
      <.text_field params={@params} field="index" label="Index" />
      <.text_field params={@params} field="source_type" label="Source Type" />
      <.secret_field params={@params} field="hec_token" label="HEC Token" required />
      <.checkbox_field params={@params} field="tls_verify" label="Verify TLS" />
      <.checkbox_field params={@params} field="acknowledgements" label="HEC Acknowledgements" />
    </div>
    """
  end

  def type_fields(%{params: %{"sink_type" => "http"}} = assigns) do
    ~H"""
    <div class="grid gap-4 md:grid-cols-2">
      <.text_field params={@params} field="endpoint" label="Endpoint" required />
      <.select_field params={@params} field="method" label="Method" options={[{"POST", "POST"}, {"PUT", "PUT"}]} />
      <.select_field params={@params} field="auth_type" label="Authentication" options={[{"None", "none"}, {"Bearer", "bearer"}, {"Basic", "basic"}]} />
      <.secret_field params={@params} field="bearer_token" label="Bearer Token" />
      <.text_field params={@params} field="basic_username" label="Basic Username" />
      <.secret_field params={@params} field="basic_password" label="Basic Password" />
      <.checkbox_field params={@params} field="tls_verify" label="Verify TLS" />
    </div>
    """
  end

  def type_fields(%{params: %{"sink_type" => "syslog"}} = assigns) do
    ~H"""
    <div class="grid gap-4 md:grid-cols-2">
      <.text_field params={@params} field="host" label="Host" required />
      <.text_field params={@params} field="port" label="Port" required />
      <.select_field params={@params} field="protocol" label="Protocol" options={[{"TCP", "tcp"}, {"UDP", "udp"}]} />
      <.select_field params={@params} field="format" label="Format" options={[{"RFC 3164", "rfc3164"}, {"RFC 5424", "rfc5424"}]} />
      <.checkbox_field params={@params} field="tls_enabled" label="Use TLS" />
      <.checkbox_field params={@params} field="tls_verify" label="Verify TLS" />
    </div>
    """
  end

  def type_fields(%{params: %{"sink_type" => "kafka"}} = assigns) do
    ~H"""
    <div class="grid gap-4 md:grid-cols-2">
      <.text_field params={@params} field="bootstrap_servers" label="Bootstrap Servers" required />
      <.text_field params={@params} field="topic" label="Topic" required />
      <.select_field params={@params} field="sasl_mechanism" label="SASL Mechanism" options={[{"None", "none"}, {"Plain", "plain"}, {"SCRAM SHA-256", "scram-sha-256"}, {"SCRAM SHA-512", "scram-sha-512"}]} />
      <.text_field params={@params} field="sasl_username" label="SASL Username" />
      <.secret_field params={@params} field="sasl_password" label="SASL Password" />
      <.select_field params={@params} field="compression" label="Compression" options={[{"None", "none"}, {"gzip", "gzip"}, {"snappy", "snappy"}, {"lz4", "lz4"}, {"zstd", "zstd"}]} />
      <.checkbox_field params={@params} field="tls_enabled" label="Use TLS" />
      <.checkbox_field params={@params} field="tls_verify" label="Verify TLS" />
    </div>
    """
  end

  def type_fields(%{params: %{"sink_type" => "s3"}} = assigns) do
    ~H"""
    <div class="grid gap-4 md:grid-cols-2">
      <.text_field params={@params} field="bucket" label="Bucket" required />
      <.text_field params={@params} field="region" label="Region" required />
      <.text_field params={@params} field="endpoint" label="Custom Endpoint" />
      <.text_field params={@params} field="prefix" label="Prefix" />
      <.secret_field params={@params} field="access_key_id" label="Access Key ID" required />
      <.secret_field params={@params} field="secret_access_key" label="Secret Access Key" required />
      <.select_field params={@params} field="compression" label="Compression" options={[{"None", "none"}, {"gzip", "gzip"}]} />
      <.select_field params={@params} field="encoding" label="Encoding" options={[{"NDJSON", "ndjson"}, {"JSON", "json"}]} />
    </div>
    """
  end

  def type_fields(assigns) do
    ~H"""
    <div class="grid gap-4 md:grid-cols-2">
      <.text_field params={@params} field="path_template" label="Path Template" required />
      <.select_field params={@params} field="encoding" label="Encoding" options={[{"NDJSON", "ndjson"}, {"JSON", "json"}, {"Text", "text"}]} />
    </div>
    """
  end

  attr(:params, :map, required: true)
  attr(:field, :string, required: true)
  attr(:label, :string, required: true)
  attr(:required, :boolean, default: false)

  def text_field(assigns) do
    ~H"""
    <div>
      <label class="mb-1 block text-sm font-medium text-gray-700" for={"sink-#{@field}"}><%= @label %></label>
      <input id={"sink-#{@field}"} name={"sink[#{@field}]"} value={Map.get(@params, @field, "")} required={@required} class="w-full rounded border border-gray-300 px-3 py-2 text-sm" />
    </div>
    """
  end

  attr(:params, :map, required: true)
  attr(:field, :string, required: true)
  attr(:label, :string, required: true)
  attr(:required, :boolean, default: false)

  def secret_field(assigns) do
    ~H"""
    <div>
      <label class="mb-1 block text-sm font-medium text-gray-700" for={"sink-#{@field}"}><%= @label %></label>
      <input id={"sink-#{@field}"} name={"sink[#{@field}]"} value={Map.get(@params, @field, "")} type="password" required={@required} autocomplete="new-password" class="w-full rounded border border-gray-300 px-3 py-2 text-sm" />
    </div>
    """
  end

  attr(:params, :map, required: true)
  attr(:field, :string, required: true)
  attr(:label, :string, required: true)
  attr(:options, :list, required: true)

  def select_field(assigns) do
    ~H"""
    <div>
      <label class="mb-1 block text-sm font-medium text-gray-700" for={"sink-#{@field}"}><%= @label %></label>
      <select id={"sink-#{@field}"} name={"sink[#{@field}]"} class="w-full rounded border border-gray-300 px-3 py-2 text-sm">
        <%= for {label, value} <- @options do %>
          <option value={value} selected={to_string(Map.get(@params, @field, "")) == to_string(value)}><%= label %></option>
        <% end %>
      </select>
    </div>
    """
  end

  attr(:params, :map, required: true)
  attr(:field, :string, required: true)
  attr(:label, :string, required: true)

  def checkbox_field(assigns) do
    ~H"""
    <label class="flex items-center gap-2 self-end rounded border border-gray-200 px-3 py-2 text-sm font-medium text-gray-700">
      <input type="hidden" name={"sink[#{@field}]"} value="false" />
      <input type="checkbox" name={"sink[#{@field}]"} value="true" checked={truthy?(Map.get(@params, @field))} class="rounded border-gray-300" />
      <span><%= @label %></span>
    </label>
    """
  end

  defp save_sink(%{assigns: %{mode: :new}} = socket, params) do
    case Forwarding.create_sink(socket.assigns.pool.id, params, socket.assigns.current_user) do
      {:ok, _sink} ->
        {:noreply,
         socket
         |> put_flash(:info, "Forwarding sink created. Deployment remains an explicit action.")
         |> push_navigate(to: "/pools/#{socket.assigns.pool.id}/forwarding")}

      {:error, reason} ->
        {:noreply, assign(socket, params: params, errors: errors_from_reason(reason))}
    end
  end

  defp save_sink(%{assigns: %{mode: :edit}} = socket, params) do
    case Forwarding.update_sink(
           socket.assigns.pool.id,
           socket.assigns.sink.id,
           params,
           socket.assigns.current_user
         ) do
      {:ok, _sink} ->
        {:noreply,
         socket
         |> put_flash(:info, "Forwarding sink saved. Deployment remains an explicit action.")
         |> push_navigate(to: "/pools/#{socket.assigns.pool.id}/forwarding")}

      {:error, reason} ->
        {:noreply, assign(socket, params: params, errors: errors_from_reason(reason))}
    end
  end

  defp validate_params(params, socket) do
    sink_type = Map.get(params, "sink_type", "file")

    []
    |> add_if(blank?(Map.get(params, "name")), "name can't be blank")
    |> add_schema_errors(SinkConfigSchema.validate(sink_type, params))
    |> add_secret_errors(sink_type, params, socket.assigns.mode)
  end

  defp add_if(errors, true, message), do: [message | errors]
  defp add_if(errors, false, _message), do: errors

  defp add_schema_errors(errors, {:ok, _config}), do: errors

  defp add_schema_errors(errors, {:error, schema_errors}) do
    errors ++ Enum.map(schema_errors, fn {field, message} -> "#{field} #{message}" end)
  end

  defp add_secret_errors(errors, sink_type, params, :new) do
    sink_type
    |> SinkConfigSchema.required_secret_fields(params)
    |> Enum.reduce(errors, fn field, acc ->
      add_if(acc, blank_or_mask?(Map.get(params, field)), "#{field} can't be blank")
    end)
  end

  defp add_secret_errors(errors, _sink_type, _params, :edit), do: errors

  defp errors_from_reason(%Ecto.Changeset{} = changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, _opts} -> message end)
    |> Enum.flat_map(fn {field, messages} ->
      Enum.map(messages, fn message -> "#{field} #{message}" end)
    end)
  end

  defp errors_from_reason(reason), do: [format_error(reason)]

  defp format_error(%Ecto.Changeset{} = changeset),
    do: errors_from_reason(changeset) |> Enum.join(", ")

  defp format_error(reason), do: "Forwarding operation failed: #{inspect(reason)}"

  defp params_from_sink(%ForwardingSink{} = sink) do
    sink
    |> config_map()
    |> Map.merge(%{
      "name" => sink.name,
      "sink_type" => sink.sink_type,
      "enabled" => sink.enabled
    })
    |> Map.merge(masked_secret_params(sink.id))
    |> merge_defaults()
  end

  defp masked_secret_params(sink_id) do
    sink_id
    |> Forwarding.masked_secrets()
    |> Map.new(fn %{secret_name: name, masked: masked} -> {name, masked || "********"} end)
  end

  defp config_map(%ForwardingSink{} = sink) do
    case Jason.decode(sink.config || "") do
      {:ok, config} when is_map(config) -> config
      _error -> %{}
    end
  end

  defp merge_defaults(params) do
    sink_type = Map.get(params, "sink_type", "file")
    Map.merge(default_params(sink_type), params)
  end

  defp merge_current_params(socket, params) do
    socket.assigns.params
    |> Map.merge(params)
    |> merge_defaults()
  end

  defp preserve_name(params, previous), do: Map.put(params, "name", Map.get(previous, "name", ""))

  defp default_params("splunk_hec") do
    %{
      "name" => "",
      "sink_type" => "splunk_hec",
      "enabled" => "true",
      "endpoint" => "https://splunk.example:8088/services/collector/event",
      "index" => "main",
      "source_type" => "ravenwire",
      "hec_token" => "",
      "tls_verify" => "true",
      "acknowledgements" => "false"
    }
  end

  defp default_params("http") do
    %{
      "name" => "",
      "sink_type" => "http",
      "enabled" => "true",
      "endpoint" => "https://collector.example/events",
      "method" => "POST",
      "auth_type" => "none",
      "bearer_token" => "",
      "basic_username" => "",
      "basic_password" => "",
      "tls_verify" => "true"
    }
  end

  defp default_params("syslog") do
    %{
      "name" => "",
      "sink_type" => "syslog",
      "enabled" => "true",
      "host" => "syslog.example",
      "port" => "6514",
      "protocol" => "tcp",
      "format" => "rfc5424",
      "tls_enabled" => "true",
      "tls_verify" => "true"
    }
  end

  defp default_params("kafka") do
    %{
      "name" => "",
      "sink_type" => "kafka",
      "enabled" => "true",
      "bootstrap_servers" => "kafka.example:9092",
      "topic" => "ravenwire-events",
      "sasl_mechanism" => "none",
      "sasl_username" => "",
      "sasl_password" => "",
      "compression" => "none",
      "tls_enabled" => "false",
      "tls_verify" => "true"
    }
  end

  defp default_params("s3") do
    %{
      "name" => "",
      "sink_type" => "s3",
      "enabled" => "true",
      "bucket" => "ravenwire-events",
      "region" => "us-east-1",
      "endpoint" => "",
      "prefix" => "events/",
      "access_key_id" => "",
      "secret_access_key" => "",
      "compression" => "none",
      "encoding" => "ndjson"
    }
  end

  defp default_params(_type) do
    %{
      "name" => "",
      "sink_type" => "file",
      "enabled" => "true",
      "path_template" => "/var/log/ravenwire/events.ndjson",
      "encoding" => "ndjson"
    }
  end

  defp result_flash_kind(result) do
    if Map.get(result, :success) || Map.get(result, "success"), do: :info, else: :error
  end

  defp sink_type_label("splunk_hec"), do: "Splunk HEC"
  defp sink_type_label("http"), do: "HTTP"
  defp sink_type_label("syslog"), do: "Syslog"
  defp sink_type_label("kafka"), do: "Kafka"
  defp sink_type_label("s3"), do: "S3"
  defp sink_type_label("file"), do: "File"
  defp sink_type_label(value), do: Formatters.display(value)

  defp truthy?(value), do: value in [true, "true", "1", 1, "on"]
  defp blank?(value), do: is_nil(value) or String.trim(to_string(value)) == ""

  defp blank_or_mask?(value),
    do: blank?(value) or String.match?(String.trim(to_string(value)), ~r/^\*+$/)
end
