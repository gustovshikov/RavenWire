defmodule ConfigManagerWeb.PcapLive.RequestDetailLive do
  @moduledoc "PCAP request detail."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Auth.Policy
  alias ConfigManager.Pcap
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pcap.get_request_for_actor(id, socket.assigns.current_user) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "PCAP Request Not Found")}

      request ->
        if connected?(socket),
          do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pcap_request:#{request.id}")

        {:ok,
         assign(socket,
           not_found: false,
           page_title: "PCAP Request",
           request: request,
           can_download: Policy.has_permission?(socket.assigns.current_user.role, "pcap:download")
         )}
    end
  end

  @impl true
  def handle_info({:pcap_request, request}, socket) do
    {:noreply, assign(socket, :request, request)}
  end

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-10">
      <a href="/pcap/requests" class="text-sm text-blue-600 hover:underline">Back to PCAP requests</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">PCAP Request Not Found</h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-5xl px-6 py-6">
      <a href="/pcap/requests" class="text-sm text-blue-600 hover:underline">Back to PCAP requests</a>
      <div class="mt-2 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900"><%= @request.sensor_name %> PCAP Request</h1>
          <p class="font-mono text-xs text-gray-500"><%= @request.id %></p>
        </div>
        <div class="flex gap-2">
          <a href={"/pcap/requests/#{@request.id}/manifest"} class="rounded border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">Manifest</a>
          <%= if @request.status == "completed" and @can_download do %>
            <a href={"/pcap/requests/#{@request.id}/download"} class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Download</a>
          <% end %>
        </div>
      </div>

      <section class="mt-6 rounded border border-gray-200 bg-white p-5">
        <dl class="grid gap-4 text-sm md:grid-cols-3">
          <.field label="Status" value={String.capitalize(@request.status)} />
          <.field label="Submitted By" value={@request.actor} />
          <.field label="Submitted At" value={Formatters.format_utc(@request.inserted_at)} />
          <.field label="Search Type" value={String.replace(@request.search_type, "_", " ")} />
          <.field label="File Size" value={format_size(@request.file_size_bytes)} />
          <.field label="Expires At" value={Formatters.format_utc(@request.expires_at)} />
        </dl>
        <%= if @request.error_reason do %>
          <p class="mt-4 rounded bg-red-50 p-3 text-sm text-red-700"><%= @request.error_reason %></p>
        <% end %>
      </section>

      <section class="mt-5 rounded border border-gray-200 bg-white p-5">
        <h2 class="text-lg font-semibold text-gray-900">Search Parameters</h2>
        <pre class="mt-3 overflow-auto rounded bg-gray-950 p-4 text-xs text-gray-100"><%= Jason.encode!(@request.search_params || %{}, pretty: true) %></pre>
      </section>
    </main>
    """
  end

  attr(:label, :string, required: true)
  attr(:value, :any, required: true)

  defp field(assigns) do
    ~H"""
    <div>
      <dt class="text-xs font-medium uppercase text-gray-500"><%= @label %></dt>
      <dd class="mt-1 text-gray-900"><%= @value || "—" %></dd>
    </div>
    """
  end

  defp format_size(nil), do: "—"
  defp format_size(bytes), do: "#{bytes} B"
end
