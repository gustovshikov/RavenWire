defmodule ConfigManagerWeb.AdminLive.ApiTokensLive do
  @moduledoc "Platform-admin API token management page."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Auth
  alias ConfigManager.Auth.{ApiToken, Policy}
  alias ConfigManagerWeb.AuthHelpers

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:permissions, Policy.canonical_permissions())
     |> assign(:created_token, nil)
     |> refresh()}
  end

  @impl true
  def handle_event("create_token", %{"api_token" => params}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "tokens:manage", "admin:create_api_token"),
         {:ok, user} <- fetch_user(params["user_id"]),
         attrs <- normalize_token_params(params),
         {:ok, token, raw_token} <-
           Auth.create_api_token(user, attrs, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "API token created. Raw token shown once.")
       |> assign(:created_token, %{name: token.name, raw: raw_token})
       |> refresh()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Token owner not found.")}

      {:error, changeset} ->
        {:noreply, put_flash(socket, :error, changeset_error(changeset))}
    end
  end

  def handle_event("revoke_token", %{"id" => id}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "tokens:manage", "admin:revoke_api_token"),
         {:ok, token} <- fetch_token(id),
         {:ok, _revoked} <- Auth.revoke_api_token(token, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "API token revoked.")
       |> assign(:created_token, nil)
       |> refresh()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, :not_found} ->
        {:noreply, socket |> put_flash(:error, "API token not found.") |> refresh()}

      {:error, changeset} ->
        {:noreply, put_flash(socket, :error, changeset_error(changeset))}
    end
  end

  defp refresh(socket) do
    users = Auth.list_users()

    assign(socket,
      users: users,
      tokens: Auth.list_api_tokens(),
      default_user_id:
        socket.assigns[:current_user].id || (List.first(users) && List.first(users).id)
    )
  end

  defp fetch_user(id) do
    case Auth.get_user(id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  defp fetch_token(id) do
    {:ok, Auth.get_api_token!(id)}
  rescue
    Ecto.NoResultsError -> {:error, :not_found}
  end

  defp normalize_token_params(params) do
    %{
      name: params["name"],
      permissions: Map.get(params, "permissions", []),
      expires_at: parse_expires_on(params["expires_on"])
    }
  end

  defp parse_expires_on(nil), do: nil
  defp parse_expires_on(""), do: nil

  defp parse_expires_on(value) do
    case Date.from_iso8601(value) do
      {:ok, date} -> DateTime.new!(date, ~T[23:59:59], "Etc/UTC")
      _ -> nil
    end
  end

  defp changeset_error(changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.flat_map(fn {field, messages} -> Enum.map(messages, &"#{field} #{&1}") end)
    |> Enum.join("; ")
    |> then(fn
      "" -> "Validation failed."
      message -> message
    end)
  end

  defp status(%{revoked_at: %DateTime{}}), do: {"revoked", "bg-red-100 text-red-800"}

  defp status(%{expires_at: %DateTime{} = expires_at}) do
    if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
      {"active", "bg-green-100 text-green-800"}
    else
      {"expired", "bg-yellow-100 text-yellow-800"}
    end
  end

  defp status(_token), do: {"active", "bg-green-100 text-green-800"}

  defp format_datetime(nil), do: "—"
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">API Tokens</h1>
          <p class="mt-1 text-sm text-gray-500">Create scoped bearer tokens for automation. Raw token values are shown only once.</p>
        </div>
        <div class="flex items-center gap-3 text-sm">
          <a href="/admin/users" class="text-blue-600 hover:underline">Users</a>
          <a href="/admin/roles" class="text-blue-600 hover:underline">Roles</a>
        </div>
      </div>

      <%= if @created_token do %>
        <section class="mb-6 rounded border border-yellow-300 bg-yellow-50 p-4 text-sm text-yellow-900">
          <div class="font-semibold">Raw token for <%= @created_token.name %></div>
          <code class="mt-2 block break-all rounded bg-white px-3 py-2 font-mono text-yellow-950">
            <%= @created_token.raw %>
          </code>
        </section>
      <% end %>

      <section class="mb-8 rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <h2 class="mb-4 text-lg font-semibold text-gray-900">Create Token</h2>
        <form phx-submit="create_token" class="space-y-4">
          <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
            <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="api_token[name]" placeholder="token name" required />
            <select class="rounded border border-gray-300 px-3 py-2 text-sm" name="api_token[user_id]">
              <%= for user <- @users do %>
                <option value={user.id} selected={user.id == @default_user_id}>
                  <%= user.username %>
                </option>
              <% end %>
            </select>
            <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="api_token[expires_on]" type="date" />
          </div>

          <div>
            <div class="mb-2 text-sm font-medium text-gray-700">Permissions</div>
            <div class="grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-3">
              <%= for permission <- @permissions do %>
                <label class="flex items-center gap-2 rounded border border-gray-200 px-3 py-2 text-sm">
                  <input type="checkbox" name="api_token[permissions][]" value={permission} class="rounded border-gray-300" />
                  <span class="font-mono text-xs text-gray-700"><%= permission %></span>
                </label>
              <% end %>
            </div>
          </div>

          <button class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700" type="submit">
            Create Token
          </button>
        </form>
      </section>

      <section class="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-gray-200 bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <th class="px-4 py-3 font-medium">Name</th>
              <th class="px-4 py-3 font-medium">Owner</th>
              <th class="px-4 py-3 font-medium">Permissions</th>
              <th class="px-4 py-3 font-medium">Expires</th>
              <th class="px-4 py-3 font-medium">Status</th>
              <th class="px-4 py-3 font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            <%= if @tokens == [] do %>
              <tr>
                <td class="px-4 py-8 text-center text-gray-400" colspan="6">No API tokens.</td>
              </tr>
            <% end %>
            <%= for token <- @tokens do %>
              <% {label, class} = status(token) %>
              <tr class="border-b border-gray-100 align-top last:border-0">
                <td class="px-4 py-3 font-semibold text-gray-900"><%= token.name %></td>
                <td class="px-4 py-3 text-gray-700"><%= token.user && token.user.username %></td>
                <td class="px-4 py-3">
                  <div class="flex flex-wrap gap-1">
                    <%= for permission <- ApiToken.permissions_list(token) do %>
                      <span class="rounded bg-gray-100 px-2 py-1 font-mono text-xs text-gray-700"><%= permission %></span>
                    <% end %>
                  </div>
                </td>
                <td class="px-4 py-3 text-gray-600"><%= format_datetime(token.expires_at) %></td>
                <td class="px-4 py-3">
                  <span class={"rounded px-2.5 py-0.5 text-xs font-medium #{class}"}><%= label %></span>
                </td>
                <td class="px-4 py-3">
                  <%= if token.revoked_at == nil do %>
                    <button
                      phx-click="revoke_token"
                      phx-value-id={token.id}
                      data-confirm="Revoke this API token?"
                      class="rounded bg-red-100 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-200"
                    >
                      Revoke
                    </button>
                  <% else %>
                    <span class="text-xs text-gray-400">Revoked</span>
                  <% end %>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </section>
    </div>
    """
  end
end
