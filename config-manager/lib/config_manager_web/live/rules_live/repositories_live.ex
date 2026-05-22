defmodule ConfigManagerWeb.RulesLive.RepositoriesLive do
  @moduledoc "Rule repository management page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.RulesLive.Helpers

  alias ConfigManager.Rules
  alias ConfigManager.Rules.RuleRepository
  alias ConfigManagerWeb.Formatters

  @repo_types [
    {"ET Open", "et_open"},
    {"Snort Community", "snort_community"},
    {"Custom", "custom"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rule_repositories")

    {:ok,
     socket
     |> assign(:page_title, "Rule Repositories")
     |> assign(:repo_types, @repo_types)
     |> assign(:form, repository_form())
     |> load_repositories()}
  end

  @impl true
  def handle_info(_message, socket), do: {:noreply, load_repositories(socket)}

  @impl true
  def handle_event("validate", %{"repository" => params}, socket) do
    changeset =
      %RuleRepository{}
      |> RuleRepository.changeset(params)
      |> Map.put(:action, :validate)

    {:noreply, assign(socket, :form, to_form(changeset, as: :repository))}
  end

  def handle_event("create", %{"repository" => params}, socket) do
    if can_manage_rules?(socket.assigns.current_user) do
      case Rules.create_repository(params, socket.assigns.current_user) do
        {:ok, _repository} ->
          {:noreply,
           socket
           |> assign(:form, repository_form())
           |> put_flash(:info, "Repository added.")
           |> load_repositories()}

        {:error, %Ecto.Changeset{} = changeset} ->
          {:noreply,
           assign(socket, :form, to_form(%{changeset | action: :insert}, as: :repository))}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Repository add failed: #{inspect(reason)}")}
      end
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  def handle_event("update_now", %{"id" => id}, socket) do
    with :ok <- authorize_manage(socket),
         %RuleRepository{} = repository <- Rules.get_repository(id),
         {:ok, :updating} <- Rules.update_repository(repository, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "Repository update started.")
       |> load_repositories()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      nil ->
        {:noreply, put_flash(socket, :error, "Repository not found.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Repository update failed: #{inspect(reason)}")}
    end
  end

  def handle_event("delete", %{"id" => id}, socket) do
    with :ok <- authorize_manage(socket),
         %RuleRepository{} = repository <- Rules.get_repository(id),
         {:ok, _deleted} <- Rules.delete_repository(repository, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "Repository deleted. Imported rules were preserved.")
       |> load_repositories()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      nil ->
        {:noreply, put_flash(socket, :error, "Repository not found.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Repository delete failed: #{inspect(reason)}")}
    end
  end

  defp load_repositories(socket), do: assign(socket, :repositories, Rules.list_repositories())

  defp repository_form(attrs \\ %{}) do
    %RuleRepository{}
    |> RuleRepository.changeset(attrs)
    |> to_form(as: :repository)
  end

  defp authorize_manage(socket) do
    if can_manage_rules?(socket.assigns.current_user), do: :ok, else: {:error, :forbidden}
  end

  defp form_errors(form) do
    if form.source.action do
      form.source.errors
      |> Enum.map(fn {field, {message, _opts}} ->
        "#{Phoenix.Naming.humanize(field)} #{message}"
      end)
    else
      []
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Rule Repositories</h1>
        <p class="text-sm text-gray-500">Add external Suricata rule archives and import updates on demand.</p>
      </div>

      <.rules_nav active="repositories" />

      <%= if can_manage_rules?(@current_user) do %>
        <form phx-submit="create" phx-change="validate" class="mb-4 grid gap-3 rounded border border-gray-200 bg-white p-4 text-sm md:grid-cols-4">
          <label class="block">
            <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Name</span>
            <input name="repository[name]" value={@form[:name].value} class="w-full rounded border border-gray-300 px-3 py-2" />
          </label>
          <label class="block md:col-span-2">
            <span class="mb-1 block text-xs font-medium uppercase text-gray-500">URL</span>
            <input name="repository[url]" value={@form[:url].value} placeholder="https://example.test/rules.tar.gz" class="w-full rounded border border-gray-300 px-3 py-2" />
          </label>
          <label class="block">
            <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Type</span>
            <select name="repository[repo_type]" class="w-full rounded border border-gray-300 px-3 py-2">
              <%= for {label, value} <- @repo_types do %>
                <option value={value} selected={(@form[:repo_type].value || "custom") == value}><%= label %></option>
              <% end %>
            </select>
          </label>
          <div class="md:col-span-4 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div class="text-sm text-red-700">
              <%= for error <- form_errors(@form) do %>
                <div><%= error %></div>
              <% end %>
            </div>
            <button type="submit" class="w-fit rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Add Repository</button>
          </div>
        </form>
      <% end %>

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @repositories == [] do %>
          <p class="p-6 text-sm text-gray-600">No rule repositories configured.</p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                  <th class="px-4 py-3 font-medium">Name</th>
                  <th class="px-4 py-3 font-medium">URL</th>
                  <th class="px-4 py-3 font-medium">Type</th>
                  <th class="px-4 py-3 font-medium">Last Updated</th>
                  <th class="px-4 py-3 font-medium">Rules</th>
                  <th class="px-4 py-3 font-medium">Status</th>
                  <%= if can_manage_rules?(@current_user) do %>
                    <th class="px-4 py-3 font-medium">Actions</th>
                  <% end %>
                </tr>
              </thead>
              <tbody>
                <%= for repository <- @repositories do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <th class="px-4 py-3 font-medium text-gray-900"><%= repository.name %></th>
                    <td class="max-w-md break-all px-4 py-3 text-gray-700"><%= repository.url %></td>
                    <td class="px-4 py-3 text-gray-700"><%= repository.repo_type %></td>
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.format_utc(repository.last_updated_at) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= repository.rule_count %></td>
                    <td class="px-4 py-3">
                      <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{repo_status_class(repository.last_update_status)}"}>
                        <%= repo_status_label(repository.last_update_status) %>
                      </span>
                      <%= if repository.last_update_error do %>
                        <div class="mt-1 max-w-xs break-words text-xs text-red-700"><%= repository.last_update_error %></div>
                      <% end %>
                    </td>
                    <%= if can_manage_rules?(@current_user) do %>
                      <td class="px-4 py-3">
                        <div class="flex flex-wrap gap-2">
                          <button type="button" phx-click="update_now" phx-value-id={repository.id} disabled={repository.last_update_status == "updating"} class="rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white disabled:cursor-not-allowed disabled:bg-gray-300 hover:bg-blue-700">
                            <%= if repository.last_update_status == "updating", do: "Updating", else: "Update Now" %>
                          </button>
                          <button type="button" phx-click="delete" phx-value-id={repository.id} data-confirm={"Delete #{repository.name}? Imported rules will be preserved."} class="rounded border border-red-300 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50">Delete</button>
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
    </main>
    """
  end
end
