defmodule ConfigManagerWeb.PcapLive.ManifestLive do
  @moduledoc "PCAP chain-of-custody manifest view."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Pcap

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pcap.get_request_for_actor(id, socket.assigns.current_user) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "PCAP Manifest Not Found")}

      request ->
        {:ok,
         assign(socket,
           not_found: false,
           page_title: "PCAP Manifest",
           request: request,
           manifest: Pcap.manifest(request)
         )}
    end
  end

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-10">
      <a href="/pcap/requests" class="text-sm text-blue-600 hover:underline">Back to PCAP requests</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">PCAP Manifest Not Found</h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-5xl px-6 py-6">
      <a href={"/pcap/requests/#{@request.id}"} class="text-sm text-blue-600 hover:underline">Back to request</a>
      <div class="mt-2 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Chain-of-Custody Manifest</h1>
          <p class="font-mono text-xs text-gray-500"><%= @request.id %></p>
        </div>
        <a href={"/pcap/requests/#{@request.id}/manifest/export"} class="rounded border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">Export JSON</a>
      </div>

      <section class="mt-6 rounded border border-gray-200 bg-white p-5">
        <p class="text-xs font-medium uppercase text-gray-500">Integrity Hash</p>
        <p class="mt-1 break-all font-mono text-sm text-gray-900"><%= @manifest.integrity_hash %></p>
      </section>

      <section class="mt-5 rounded border border-gray-200 bg-white">
        <div class="border-b border-gray-200 px-5 py-3">
          <h2 class="text-lg font-semibold text-gray-900">Custody Events</h2>
        </div>
        <div class="divide-y divide-gray-100">
          <%= if @manifest.custody_events == [] do %>
            <p class="px-5 py-6 text-sm text-gray-500">No custody events have been recorded yet.</p>
          <% end %>
          <%= for event <- @manifest.custody_events do %>
            <article class="px-5 py-4">
              <div class="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                <h3 class="font-medium text-gray-900"><%= String.replace(event.event_type, "_", " ") %></h3>
                <time class="text-sm text-gray-500"><%= event.timestamp %></time>
              </div>
              <p class="mt-1 text-sm text-gray-600"><%= event.actor_display_name || event.actor_username %></p>
              <pre class="mt-3 overflow-auto rounded bg-gray-50 p-3 text-xs text-gray-700"><%= Jason.encode!(event.detail || %{}, pretty: true) %></pre>
            </article>
          <% end %>
        </div>
      </section>
    </main>
    """
  end
end
