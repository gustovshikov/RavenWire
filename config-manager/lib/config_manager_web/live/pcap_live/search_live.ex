defmodule ConfigManagerWeb.PcapLive.SearchLive do
  @moduledoc "Browser PCAP search and carve submission workflow."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Pcap
  alias ConfigManager.Pcap.{CarveRequest, CommunityId, SearchParams, StatusPoller}

  @search_modes [
    {"Community ID", "community_id"},
    {"Time Range", "time_range"},
    {"5-Tuple", "five_tuple"},
    {"Alert ID", "alert_id"},
    {"Zeek UID", "zeek_uid"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(
       page_title: "PCAP Search",
       form: default_form(),
       calc: %{},
       calc_result: nil,
       errors: %{},
       requests: [],
       sensors: Pcap.sensor_options(),
       search_modes: @search_modes
     )}
  end

  @impl true
  def handle_event("validate", %{"search" => params}, socket) do
    form = normalize_form(params)
    errors = validation_errors(form)
    {:noreply, assign(socket, form: form, errors: errors)}
  end

  def handle_event("submit", %{"search" => params}, socket) do
    form = normalize_form(params)

    case Pcap.submit_search(form, socket.assigns.current_user) do
      {:ok, requests} ->
        if connected?(socket) do
          Enum.each(requests, fn request ->
            Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pcap_request:#{request.id}")

            unless CarveRequest.terminal?(request) do
              StatusPoller.start(request)
            end
          end)
        end

        {:noreply,
         socket
         |> assign(form: form, errors: %{}, requests: requests)
         |> put_flash(:info, "PCAP search submitted.")}

      {:error, {:validation, errors}} ->
        {:noreply, assign(socket, form: form, errors: errors)}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(form: form)
         |> put_flash(:error, "PCAP search failed: #{format_reason(reason)}")}
    end
  end

  def handle_event("calculate_community_id", %{"calc" => params}, socket) do
    case CommunityId.compute(params) do
      {:ok, community_id} ->
        form = Map.put(socket.assigns.form, "community_id", community_id)

        {:noreply,
         assign(socket,
           calc: params,
           calc_result: community_id,
           form: form,
           errors: validation_errors(form)
         )}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(calc: params, calc_result: nil)
         |> put_flash(:error, "Community ID calculation failed: #{format_reason(reason)}")}
    end
  end

  @impl true
  def handle_info({:pcap_request, request}, socket) do
    requests =
      socket.assigns.requests
      |> Enum.map(fn existing -> if existing.id == request.id, do: request, else: existing end)

    {:noreply, assign(socket, :requests, requests)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-6xl px-6 py-6">
      <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">PCAP Search</h1>
          <p class="text-sm text-gray-600">Search sensor packet rings by Community ID, time range, 5-tuple, alert ID, or Zeek UID.</p>
        </div>
        <a href="/pcap/requests" class="text-sm text-blue-600 hover:underline">Request History</a>
      </div>

      <div class="mt-6 grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        <section class="rounded border border-gray-200 bg-white p-5">
          <form phx-change="validate" phx-submit="submit" class="space-y-5">
            <div>
              <label class="mb-1 block text-sm font-medium text-gray-700" for="search-type">Search Mode</label>
              <select id="search-type" name="search[search_type]" class="w-full rounded border border-gray-300 px-3 py-2 text-sm">
                <%= for {label, value} <- @search_modes do %>
                  <option value={value} selected={@form["search_type"] == value}><%= label %></option>
                <% end %>
              </select>
              <.field_errors errors={@errors} field="search_type" />
            </div>

            <%= if @form["search_type"] == "community_id" do %>
              <div>
                <label class="mb-1 block text-sm font-medium text-gray-700" for="community-id">Community ID</label>
                <input id="community-id" name="search[community_id]" value={@form["community_id"]} class="w-full rounded border border-gray-300 px-3 py-2 font-mono text-sm" placeholder="1:..." />
                <p class="mt-1 text-xs text-gray-500">Community ID is the primary cross-tool pivot shared by Zeek, Suricata, and downstream analytics.</p>
                <.field_errors errors={@errors} field="community_id" />
              </div>
            <% end %>

            <%= if @form["search_type"] == "five_tuple" do %>
              <div class="grid gap-3 md:grid-cols-2">
                <.text_input id="src-ip" label="Source IP" name="search[src_ip]" value={@form["src_ip"]} errors={@errors} field="src_ip" />
                <.text_input id="dst-ip" label="Destination IP" name="search[dst_ip]" value={@form["dst_ip"]} errors={@errors} field="dst_ip" />
                <.text_input id="src-port" label="Source Port" name="search[src_port]" value={@form["src_port"]} errors={@errors} field="src_port" />
                <.text_input id="dst-port" label="Destination Port" name="search[dst_port]" value={@form["dst_port"]} errors={@errors} field="dst_port" />
                <.text_input id="protocol" label="Protocol" name="search[protocol]" value={@form["protocol"]} errors={@errors} field="protocol" />
              </div>
            <% end %>

            <%= if @form["search_type"] == "alert_id" do %>
              <.text_input id="alert-id" label="Suricata SID / Alert ID" name="search[alert_id]" value={@form["alert_id"]} errors={@errors} field="alert_id" />
            <% end %>

            <%= if @form["search_type"] == "zeek_uid" do %>
              <.text_input id="zeek-uid" label="Zeek UID" name="search[zeek_uid]" value={@form["zeek_uid"]} errors={@errors} field="zeek_uid" />
            <% end %>

            <div class="grid gap-3 md:grid-cols-2">
              <.text_input id="start-time" label="Start Time UTC" name="search[start_time]" value={@form["start_time"]} errors={@errors} field="start_time" type="datetime-local" />
              <.text_input id="end-time" label="End Time UTC" name="search[end_time]" value={@form["end_time"]} errors={@errors} field="end_time" type="datetime-local" />
            </div>

            <section class="rounded border border-gray-200 p-4">
              <h2 class="text-sm font-semibold text-gray-900">Target Sensors</h2>
              <p class="mt-1 text-xs text-gray-500">If none are selected, the search targets all currently online enrolled sensors.</p>
              <%= if @sensors == [] do %>
                <p class="mt-3 text-sm text-gray-600">No enrolled sensors are available.</p>
              <% else %>
                <div class="mt-3 grid gap-2 md:grid-cols-2">
                  <%= for sensor <- @sensors do %>
                    <label class="flex items-center justify-between rounded border border-gray-200 px-3 py-2 text-sm">
                      <span class="flex items-center gap-2">
                        <input type="checkbox" name="search[sensor_pod_ids][]" value={sensor.id} checked={sensor.id in Map.get(@form, "sensor_pod_ids", [])} />
                        <span><%= sensor.name %></span>
                      </span>
                      <span class={["text-xs font-medium", if(sensor.online, do: "text-green-700", else: "text-gray-500")]}>
                        <%= if sensor.online, do: "Online", else: "Offline" %>
                      </span>
                    </label>
                  <% end %>
                </div>
              <% end %>
              <.field_errors errors={@errors} field="sensor_pod_ids" />
            </section>

            <button type="submit" class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Search PCAP</button>
          </form>
        </section>

        <section class="rounded border border-gray-200 bg-white p-5">
          <h2 class="text-lg font-semibold text-gray-900">Community ID Calculator</h2>
          <form phx-submit="calculate_community_id" class="mt-4 space-y-3">
            <.text_input id="calc-src-ip" label="Source IP" name="calc[src_ip]" value={@calc["src_ip"]} errors={%{}} field="src_ip" />
            <.text_input id="calc-dst-ip" label="Destination IP" name="calc[dst_ip]" value={@calc["dst_ip"]} errors={%{}} field="dst_ip" />
            <div class="grid gap-3 md:grid-cols-3">
              <.text_input id="calc-src-port" label="Src Port" name="calc[src_port]" value={@calc["src_port"]} errors={%{}} field="src_port" />
              <.text_input id="calc-dst-port" label="Dst Port" name="calc[dst_port]" value={@calc["dst_port"]} errors={%{}} field="dst_port" />
              <.text_input id="calc-protocol" label="Protocol" name="calc[protocol]" value={@calc["protocol"] || "tcp"} errors={%{}} field="protocol" />
            </div>
            <button type="submit" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Calculate</button>
          </form>
          <%= if @calc_result do %>
            <div class="mt-4 rounded bg-gray-50 p-3">
              <p class="text-xs font-medium uppercase text-gray-500">Computed Community ID</p>
              <p class="mt-1 break-all font-mono text-sm text-gray-900"><%= @calc_result %></p>
            </div>
          <% end %>
        </section>
      </div>

      <%= if @requests != [] do %>
        <section class="mt-6 rounded border border-gray-200 bg-white">
          <div class="border-b border-gray-200 px-5 py-3">
            <h2 class="text-lg font-semibold text-gray-900">Submitted Requests</h2>
          </div>
          <div class="divide-y divide-gray-100">
            <%= for request <- @requests do %>
              <div class="flex flex-col gap-2 px-5 py-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <a href={"/pcap/requests/#{request.id}"} class="font-medium text-blue-600 hover:underline"><%= request.sensor_name %></a>
                  <p class="text-sm text-gray-600"><%= format_search(request) %></p>
                </div>
                <.status_badge status={request.status} />
              </div>
            <% end %>
          </div>
        </section>
      <% end %>
    </main>
    """
  end

  attr(:id, :string, required: true)
  attr(:label, :string, required: true)
  attr(:name, :string, required: true)
  attr(:value, :any, default: nil)
  attr(:errors, :map, required: true)
  attr(:field, :string, required: true)
  attr(:type, :string, default: "text")

  defp text_input(assigns) do
    ~H"""
    <div>
      <label class="mb-1 block text-sm font-medium text-gray-700" for={@id}><%= @label %></label>
      <input id={@id} type={@type} name={@name} value={@value} class="w-full rounded border border-gray-300 px-3 py-2 text-sm" />
      <.field_errors errors={@errors} field={@field} />
    </div>
    """
  end

  attr(:errors, :map, required: true)
  attr(:field, :string, required: true)

  defp field_errors(assigns) do
    ~H"""
    <%= for message <- Map.get(@errors, @field, []) do %>
      <p class="mt-1 text-xs text-red-600"><%= message %></p>
    <% end %>
    """
  end

  attr(:status, :string, required: true)

  defp status_badge(assigns) do
    ~H"""
    <span class={["inline-flex w-fit rounded px-2 py-1 text-xs font-semibold", status_class(@status)]}><%= String.capitalize(@status || "unknown") %></span>
    """
  end

  defp default_form do
    %{
      "search_type" => "community_id",
      "community_id" => "",
      "src_ip" => "",
      "dst_ip" => "",
      "src_port" => "",
      "dst_port" => "",
      "protocol" => "tcp",
      "alert_id" => "",
      "zeek_uid" => "",
      "start_time" => "",
      "end_time" => "",
      "sensor_pod_ids" => []
    }
  end

  defp normalize_form(params) do
    default_form()
    |> Map.merge(params)
    |> Map.update("sensor_pod_ids", [], &List.wrap/1)
  end

  defp validation_errors(form) do
    case SearchParams.validate(form) do
      {:ok, _params} -> %{}
      {:error, errors} -> errors
    end
  end

  defp status_class("completed"), do: "bg-green-100 text-green-800"
  defp status_class("failed"), do: "bg-red-100 text-red-800"
  defp status_class("expired"), do: "bg-gray-100 text-gray-700"
  defp status_class("carving"), do: "bg-yellow-100 text-yellow-800"
  defp status_class(_status), do: "bg-blue-100 text-blue-800"

  defp format_search(%{search_type: type, search_params: params}) do
    params = params || %{}

    case type do
      "community_id" ->
        "Community ID #{Map.get(params, "community_id")}"

      "five_tuple" ->
        "#{Map.get(params, "src_ip")}:#{Map.get(params, "src_port")} -> #{Map.get(params, "dst_ip")}:#{Map.get(params, "dst_port")} #{Map.get(params, "protocol")}"

      "alert_id" ->
        "Alert ID #{Map.get(params, "alert_id") || Map.get(params, "sid")}"

      "zeek_uid" ->
        "Zeek UID #{Map.get(params, "zeek_uid")}"

      _other ->
        "Time range #{Map.get(params, "start_time")} to #{Map.get(params, "end_time")}"
    end
  end

  defp format_reason(reason), do: inspect(reason)
end
