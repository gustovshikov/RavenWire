defmodule ConfigManagerWeb.RulesLive.RulesetDetailLive do
  @moduledoc "Ruleset create, detail, edit, assignment, and deployment page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.RulesLive.Helpers

  alias ConfigManager.{Pools, Rules}
  alias ConfigManager.Rules.Ruleset
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rulesets")

    socket =
      socket
      |> assign(:page_title, page_title(socket.assigns.live_action))
      |> assign(:not_found, false)
      |> load_supporting_data()

    case socket.assigns.live_action do
      :new ->
        ruleset = %Ruleset{categories: []}
        changeset = Ruleset.create_changeset(ruleset, %{}, actor_name(socket))

        {:ok,
         socket
         |> assign(:ruleset, ruleset)
         |> assign(:effective_count, 0)
         |> assign(:pool_rows, [])
         |> assign(:selected_categories, [])
         |> assign(:form, to_form(changeset, as: :ruleset))}

      action when action in [:show, :edit] ->
        load_existing_ruleset(socket, params["id"])
    end
  end

  @impl true
  def handle_info(_message, %{assigns: %{live_action: :new}} = socket), do: {:noreply, socket}

  def handle_info(_message, socket) do
    {:noreply, reload_ruleset(socket)}
  end

  @impl true
  def handle_event("validate", %{"ruleset" => params}, socket) do
    params = normalize_ruleset_params(params)

    changeset =
      case socket.assigns.live_action do
        :new -> Ruleset.create_changeset(%Ruleset{}, params, actor_name(socket))
        _ -> Ruleset.update_changeset(socket.assigns.ruleset, params, actor_name(socket))
      end
      |> Map.put(:action, :validate)

    {:noreply,
     socket
     |> assign(:selected_categories, params["categories"] || [])
     |> assign(:form, to_form(changeset, as: :ruleset))}
  end

  def handle_event("save", %{"ruleset" => params}, socket) do
    if can_manage_rules?(socket.assigns.current_user) do
      params = normalize_ruleset_params(params)

      case save_ruleset(socket, params) do
        {:ok, ruleset} ->
          {:noreply,
           socket
           |> put_flash(:info, "Ruleset saved.")
           |> push_navigate(to: "/rules/rulesets/#{ruleset.id}")}

        {:error, %Ecto.Changeset{} = changeset} ->
          {:noreply,
           socket
           |> assign(:selected_categories, params["categories"] || [])
           |> assign(:form, to_form(%{changeset | action: :insert}, as: :ruleset))}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Ruleset save failed: #{inspect(reason)}")}
      end
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  def handle_event("delete", _params, socket) do
    with :ok <- authorize_manage(socket),
         {:ok, _deleted} <-
           Rules.delete_ruleset(socket.assigns.ruleset, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "Ruleset deleted.")
       |> push_navigate(to: "/rules/rulesets")}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Ruleset delete failed: #{inspect(reason)}")}
    end
  end

  def handle_event("add_override", %{"sid" => sid, "action" => action}, socket) do
    with :ok <- authorize_manage(socket),
         {:ok, _override} <-
           Rules.add_ruleset_override(
             socket.assigns.ruleset,
             sid,
             action,
             socket.assigns.current_user
           ) do
      {:noreply,
       socket
       |> put_flash(:info, "Override saved.")
       |> reload_ruleset()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, :rule_not_found} ->
        {:noreply, put_flash(socket, :error, "Include override SID is not in the rule store.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Override save failed: #{inspect(reason)}")}
    end
  end

  def handle_event("remove_override", %{"sid" => sid}, socket) do
    with :ok <- authorize_manage(socket),
         {:ok, _override} <-
           Rules.remove_ruleset_override(socket.assigns.ruleset, sid, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "Override removed.")
       |> reload_ruleset()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Override remove failed: #{inspect(reason)}")}
    end
  end

  def handle_event("assign_pool", %{"pool_id" => pool_id}, socket) do
    with :ok <- authorize_manage(socket),
         pool when not is_nil(pool) <- Pools.get_pool(pool_id),
         {:ok, _assignment} <-
           Rules.assign_ruleset_to_pool(
             socket.assigns.ruleset,
             pool,
             socket.assigns.current_user
           ) do
      {:noreply,
       socket
       |> put_flash(:info, "Ruleset assigned.")
       |> reload_ruleset()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      nil ->
        {:noreply, put_flash(socket, :error, "Pool not found.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Pool assignment failed: #{inspect(reason)}")}
    end
  end

  def handle_event("unassign_pool", %{"pool_id" => pool_id}, socket) do
    with :ok <- authorize_manage(socket),
         pool when not is_nil(pool) <- Pools.get_pool(pool_id),
         {:ok, _assignment} <- Rules.unassign_ruleset_from_pool(pool, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "Ruleset unassigned.")
       |> reload_ruleset()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      nil ->
        {:noreply, put_flash(socket, :error, "Pool not found.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Pool unassignment failed: #{inspect(reason)}")}
    end
  end

  def handle_event("deploy_to_pool", %{"pool_id" => pool_id}, socket) do
    if can_deploy_rules?(socket.assigns.current_user) do
      case Rules.deploy_ruleset_to_pool(pool_id, socket.assigns.current_user) do
        {:ok, %{results: results, version: version}} ->
          {:noreply,
           socket
           |> put_flash(:info, "Ruleset v#{version} deployed to #{length(results)} sensor(s).")
           |> reload_ruleset()}

        {:error, :empty_ruleset} ->
          {:noreply, put_flash(socket, :error, "Ruleset has no enabled rules to deploy.")}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Ruleset deployment failed: #{inspect(reason)}")}
      end
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  defp load_existing_ruleset(socket, id) do
    case Rules.get_ruleset(id) do
      nil ->
        {:ok,
         socket
         |> assign(:not_found, true)
         |> assign(:page_title, "Ruleset Not Found")}

      %Ruleset{} = ruleset ->
        {:ok, assign_ruleset_state(socket, ruleset)}
    end
  end

  defp reload_ruleset(%{assigns: %{ruleset: %{id: id}}} = socket) when not is_nil(id) do
    case Rules.get_ruleset(id) do
      nil -> assign(socket, :not_found, true)
      ruleset -> assign_ruleset_state(socket, ruleset)
    end
  end

  defp reload_ruleset(socket), do: socket

  defp assign_ruleset_state(socket, ruleset) do
    changeset = Ruleset.update_changeset(ruleset, %{}, actor_name(socket))

    socket
    |> assign(:not_found, false)
    |> assign(:page_title, ruleset.name || "Ruleset")
    |> assign(:ruleset, ruleset)
    |> assign(:effective_count, Rules.effective_rule_count(ruleset))
    |> assign(:pool_rows, pool_rows(ruleset))
    |> assign(:selected_categories, ruleset.categories || [])
    |> assign(:form, to_form(changeset, as: :ruleset))
  end

  defp load_supporting_data(socket) do
    assign(socket,
      categories: Rules.list_categories(),
      pools: Pools.list_pools()
    )
  end

  defp pool_rows(%Ruleset{} = ruleset) do
    Pools.list_pools()
    |> Enum.map(fn %{pool: pool, member_count: member_count} ->
      assignment = Rules.pool_assignment(pool.id)

      %{
        pool: pool,
        member_count: member_count,
        assignment: assignment,
        assigned_here?: assignment && assignment.ruleset_id == ruleset.id,
        assigned_ruleset: assignment && assignment.ruleset,
        out_of_sync_count: Rules.out_of_sync_count(pool.id)
      }
    end)
  end

  defp save_ruleset(%{assigns: %{live_action: :new}} = socket, params) do
    Rules.create_ruleset(params, socket.assigns.current_user)
  end

  defp save_ruleset(socket, params) do
    Rules.update_ruleset(socket.assigns.ruleset, params, socket.assigns.current_user)
  end

  defp normalize_ruleset_params(params) do
    categories =
      params
      |> Map.get("categories", [])
      |> List.wrap()
      |> Enum.map(&String.trim(to_string(&1)))
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()

    Map.put(params, "categories", categories)
  end

  defp authorize_manage(socket) do
    if can_manage_rules?(socket.assigns.current_user), do: :ok, else: {:error, :forbidden}
  end

  defp actor_name(%{assigns: %{current_user: %{username: username}}}), do: username
  defp actor_name(_socket), do: "system"

  defp page_title(:new), do: "New Ruleset"
  defp page_title(:edit), do: "Edit Ruleset"
  defp page_title(:show), do: "Ruleset"

  defp sorted_overrides(nil), do: []
  defp sorted_overrides(overrides), do: Enum.sort_by(overrides, & &1.sid)

  defp category_checked?(selected_categories, category) do
    category in selected_categories
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
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-12">
      <a href="/rules/rulesets" class="text-sm text-blue-600 hover:underline">Back to rulesets</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">Ruleset Not Found</h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <a href="/rules/rulesets" class="text-sm text-blue-600 hover:underline">Back to rulesets</a>
          <h1 class="mt-2 text-2xl font-bold text-gray-900">
            <%= if @live_action == :new, do: "New Ruleset", else: @ruleset.name %>
          </h1>
          <p class="text-sm text-gray-500">
            <%= if @live_action == :new do %>
              Create a deployable rule composition.
            <% else %>
              Version <%= @ruleset.version %> with <%= @effective_count %> effective rule(s).
            <% end %>
          </p>
        </div>
        <%= if @live_action == :show and can_manage_rules?(@current_user) do %>
          <div class="flex flex-wrap gap-2">
            <a href={"/rules/rulesets/#{@ruleset.id}/edit"} class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800 hover:bg-gray-50">Edit</a>
            <button type="button" phx-click="delete" data-confirm={"Delete ruleset #{@ruleset.name}?"} class="rounded border border-red-300 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50">Delete</button>
          </div>
        <% end %>
      </div>

      <.rules_nav active="rulesets" />

      <%= if @live_action in [:new, :edit] do %>
        <.ruleset_form
          form={@form}
          categories={@categories}
          selected_categories={@selected_categories}
          current_user={@current_user}
        />
      <% else %>
        <.ruleset_summary ruleset={@ruleset} effective_count={@effective_count} />
      <% end %>

      <%= if @live_action != :new do %>
        <.overrides_section ruleset={@ruleset} current_user={@current_user} />
        <.pool_assignments_section rows={@pool_rows} current_user={@current_user} />
      <% end %>
    </main>
    """
  end

  attr(:form, :any, required: true)
  attr(:categories, :list, required: true)
  attr(:selected_categories, :list, required: true)
  attr(:current_user, :map, required: true)

  def ruleset_form(assigns) do
    ~H"""
    <section class="mb-4 rounded border border-gray-200 bg-white p-4">
      <form phx-submit="save" phx-change="validate" class="space-y-4">
        <div class="grid gap-3 md:grid-cols-2">
          <label class="block">
            <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Name</span>
            <input name="ruleset[name]" value={@form[:name].value} disabled={!can_manage_rules?(@current_user)} class="w-full rounded border border-gray-300 px-3 py-2 disabled:bg-gray-100" />
          </label>
          <label class="block">
            <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Description</span>
            <input name="ruleset[description]" value={@form[:description].value} disabled={!can_manage_rules?(@current_user)} class="w-full rounded border border-gray-300 px-3 py-2 disabled:bg-gray-100" />
          </label>
        </div>

        <div>
          <div class="mb-2 text-xs font-medium uppercase text-gray-500">Categories</div>
          <input type="hidden" name="ruleset[categories][]" value="" />
          <%= if @categories == [] do %>
            <p class="text-sm text-gray-600">No categories are available.</p>
          <% else %>
            <div class="grid gap-2 text-sm md:grid-cols-3">
              <%= for category <- @categories do %>
                <label class="flex items-center gap-2 rounded border border-gray-200 px-3 py-2">
                  <input
                    type="checkbox"
                    name="ruleset[categories][]"
                    value={category.name}
                    checked={category_checked?(@selected_categories, category.name)}
                    disabled={!can_manage_rules?(@current_user)}
                    class="rounded border-gray-300"
                  />
                  <span class="truncate"><%= category.name %></span>
                  <span class="ml-auto text-xs text-gray-500"><%= category.total %></span>
                </label>
              <% end %>
            </div>
          <% end %>
        </div>

        <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div class="text-sm text-red-700">
            <%= for error <- form_errors(@form) do %>
              <div><%= error %></div>
            <% end %>
          </div>
          <%= if can_manage_rules?(@current_user) do %>
            <button type="submit" class="w-fit rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Save Ruleset</button>
          <% end %>
        </div>
      </form>
    </section>
    """
  end

  attr(:ruleset, :map, required: true)
  attr(:effective_count, :integer, required: true)

  def ruleset_summary(assigns) do
    ~H"""
    <section class="mb-4 rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Ruleset Summary</h2>
      <dl class="grid gap-3 text-sm md:grid-cols-4">
        <div>
          <dt class="text-xs font-medium uppercase text-gray-500">Description</dt>
          <dd class="mt-1 break-words text-gray-900"><%= Formatters.display(@ruleset.description) %></dd>
        </div>
        <div>
          <dt class="text-xs font-medium uppercase text-gray-500">Effective Rules</dt>
          <dd class="mt-1 text-gray-900"><%= @effective_count %></dd>
        </div>
        <div>
          <dt class="text-xs font-medium uppercase text-gray-500">Updated By</dt>
          <dd class="mt-1 text-gray-900"><%= Formatters.display(@ruleset.updated_by) %></dd>
        </div>
        <div>
          <dt class="text-xs font-medium uppercase text-gray-500">Updated At</dt>
          <dd class="mt-1 text-gray-900"><%= Formatters.format_utc(@ruleset.updated_at) %></dd>
        </div>
      </dl>
      <div class="mt-4">
        <h3 class="mb-2 text-sm font-semibold text-gray-700">Categories</h3>
        <%= if @ruleset.categories in [nil, []] do %>
          <p class="text-sm text-gray-600">No categories selected.</p>
        <% else %>
          <div class="flex flex-wrap gap-2">
            <%= for category <- @ruleset.categories do %>
              <span class="rounded bg-gray-100 px-2 py-1 text-xs font-medium text-gray-700"><%= category %></span>
            <% end %>
          </div>
        <% end %>
      </div>
    </section>
    """
  end

  attr(:ruleset, :map, required: true)
  attr(:current_user, :map, required: true)

  def overrides_section(assigns) do
    ~H"""
    <section class="mb-4 rounded border border-gray-200 bg-white p-4">
      <div class="mb-3 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <h2 class="text-lg font-semibold text-gray-900">SID Overrides</h2>
        <%= if can_manage_rules?(@current_user) do %>
          <form phx-submit="add_override" class="flex flex-wrap gap-2 text-sm">
            <input name="sid" inputmode="numeric" placeholder="SID" class="w-32 rounded border border-gray-300 px-3 py-2" />
            <select name="action" class="rounded border border-gray-300 px-3 py-2">
              <option value="include">Include</option>
              <option value="exclude">Exclude</option>
            </select>
            <button type="submit" class="rounded bg-blue-600 px-3 py-2 font-medium text-white hover:bg-blue-700">Add</button>
          </form>
        <% end %>
      </div>

      <%= if sorted_overrides(@ruleset.overrides) == [] do %>
        <p class="text-sm text-gray-600">No SID overrides configured.</p>
      <% else %>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-xs uppercase text-gray-500">
                <th class="py-2 pr-4 font-medium">SID</th>
                <th class="py-2 pr-4 font-medium">Action</th>
                <%= if can_manage_rules?(@current_user) do %>
                  <th class="py-2 font-medium">Remove</th>
                <% end %>
              </tr>
            </thead>
            <tbody>
              <%= for override <- sorted_overrides(@ruleset.overrides) do %>
                <tr class="border-b border-gray-100 last:border-0">
                  <td class="py-2 pr-4 font-mono text-xs"><%= override.sid %></td>
                  <td class="py-2 pr-4"><%= override.action %></td>
                  <%= if can_manage_rules?(@current_user) do %>
                    <td class="py-2">
                      <button type="button" phx-click="remove_override" phx-value-sid={override.sid} class="rounded border border-red-300 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50">Remove</button>
                    </td>
                  <% end %>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      <% end %>
    </section>
    """
  end

  attr(:rows, :list, required: true)
  attr(:current_user, :map, required: true)

  def pool_assignments_section(assigns) do
    ~H"""
    <section class="rounded border border-gray-200 bg-white p-4">
      <h2 class="mb-3 text-lg font-semibold text-gray-900">Pool Assignments</h2>
      <%= if @rows == [] do %>
        <p class="text-sm text-gray-600">No pools have been created.</p>
      <% else %>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-xs uppercase text-gray-500">
                <th class="py-2 pr-4 font-medium">Pool</th>
                <th class="py-2 pr-4 font-medium">Sensors</th>
                <th class="py-2 pr-4 font-medium">Assignment</th>
                <th class="py-2 pr-4 font-medium">Deployed Version</th>
                <th class="py-2 pr-4 font-medium">Sync</th>
                <th class="py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              <%= for row <- @rows do %>
                <tr class="border-b border-gray-100 last:border-0">
                  <th class="py-2 pr-4 font-medium">
                    <a href={"/pools/#{row.pool.id}"} class="text-blue-700 hover:underline"><%= row.pool.name %></a>
                  </th>
                  <td class="py-2 pr-4 text-gray-700"><%= row.member_count %></td>
                  <td class="py-2 pr-4 text-gray-700">
                    <%= cond do %>
                      <% row.assigned_here? -> %>
                        This ruleset
                      <% row.assigned_ruleset -> %>
                        <a href={"/rules/rulesets/#{row.assigned_ruleset.id}"} class="text-blue-700 hover:underline"><%= row.assigned_ruleset.name %></a>
                      <% true -> %>
                        Unassigned
                    <% end %>
                  </td>
                  <td class="py-2 pr-4 text-gray-700">
                    <%= if row.assignment, do: Formatters.display(row.assignment.deployed_rule_version), else: Formatters.display(nil) %>
                  </td>
                  <td class="py-2 pr-4">
                    <%= if row.assigned_here? do %>
                      <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{if row.out_of_sync_count == 0, do: sync_status_class(:in_sync), else: sync_status_class(:out_of_sync)}"}>
                        <%= if row.out_of_sync_count == 0, do: "In Sync", else: "#{row.out_of_sync_count} Out" %>
                      </span>
                    <% else %>
                      <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{sync_status_class(nil)}"}>No Ruleset</span>
                    <% end %>
                  </td>
                  <td class="py-2">
                    <div class="flex flex-wrap gap-2">
                      <%= if can_manage_rules?(@current_user) and !row.assigned_here? do %>
                        <button type="button" phx-click="assign_pool" phx-value-pool_id={row.pool.id} class="rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700">Assign</button>
                      <% end %>
                      <%= if can_manage_rules?(@current_user) and row.assigned_here? do %>
                        <button type="button" phx-click="unassign_pool" phx-value-pool_id={row.pool.id} class="rounded border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-800 hover:bg-gray-50">Unassign</button>
                      <% end %>
                      <%= if can_deploy_rules?(@current_user) and row.assigned_here? do %>
                        <button type="button" phx-click="deploy_to_pool" phx-value-pool_id={row.pool.id} class="rounded bg-green-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-green-800">Deploy Rules</button>
                      <% end %>
                    </div>
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
end
