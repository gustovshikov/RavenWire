defmodule ConfigManagerWeb.AdminLive.UsersLive do
  @moduledoc "Platform-admin user management page."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Auth
  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.AuthHelpers

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:roles, Policy.roles() |> Enum.sort())
     |> assign(:create_form, to_form(%{}, as: :user))
     |> assign(:update_forms, %{})
     |> assign(:reset_password, nil)
     |> refresh_users()}
  end

  @impl true
  def handle_event("create_user", %{"user" => params}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "users:manage", "admin:create_user"),
         {:ok, _user} <- Auth.create_user(params, socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "User created.")
       |> assign(:create_form, to_form(%{}, as: :user))
       |> refresh_users()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, changeset} ->
        {:noreply,
         socket
         |> put_flash(:error, changeset_error(changeset))
         |> assign(:create_form, to_form(params, as: :user))}
    end
  end

  def handle_event("update_user", %{"id" => id, "user" => params}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "users:manage", "admin:update_user"),
         {:ok, user} <- fetch_user(id),
         :ok <- prevent_self_deactivation(socket, id, params),
         {:ok, _updated} <-
           Auth.update_user(user, normalize_update_params(params), socket.assigns.current_user) do
      {:noreply, socket |> put_flash(:info, "User updated.") |> refresh_users()}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, :not_found} ->
        {:noreply, socket |> put_flash(:error, "User not found.") |> refresh_users()}

      {:error, changeset} ->
        {:noreply, put_flash(socket, :error, changeset_error(changeset))}
    end
  end

  def handle_event("disable_user", %{"id" => id}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "users:manage", "admin:disable_user"),
         :ok <- prevent_self_target(socket, id, "disable"),
         {:ok, user} <- fetch_user(id),
         {:ok, _updated} <- Auth.disable_user(user, socket.assigns.current_user) do
      {:noreply, socket |> put_flash(:info, "User disabled.") |> refresh_users()}
    else
      error -> user_action_error(socket, error)
    end
  end

  def handle_event("enable_user", %{"id" => id}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "users:manage", "admin:enable_user"),
         {:ok, user} <- fetch_user(id),
         {:ok, _updated} <- Auth.enable_user(user, socket.assigns.current_user) do
      {:noreply, socket |> put_flash(:info, "User enabled.") |> refresh_users()}
    else
      error -> user_action_error(socket, error)
    end
  end

  def handle_event("delete_user", %{"id" => id}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "users:manage", "admin:delete_user"),
         :ok <- prevent_self_target(socket, id, "delete"),
         {:ok, user} <- fetch_user(id),
         {:ok, _deleted} <- Auth.delete_user(user, socket.assigns.current_user) do
      {:noreply, socket |> put_flash(:info, "User deleted.") |> refresh_users()}
    else
      error -> user_action_error(socket, error)
    end
  end

  def handle_event("reset_password", %{"id" => id, "password" => password}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "users:manage", "admin:reset_password"),
         {:ok, user} <- fetch_user(id),
         {:ok, _updated, temporary_password} <-
           Auth.admin_reset_password(user, blank_to_nil(password), socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "Password reset. Temporary password shown once.")
       |> assign(:reset_password, %{username: user.username, password: temporary_password})
       |> refresh_users()}
    else
      error -> user_action_error(socket, error)
    end
  end

  defp refresh_users(socket) do
    users = Auth.list_users()

    assign(socket,
      users: users,
      update_forms: Map.new(users, &{&1.id, to_form(user_update_params(&1), as: :user)})
    )
  end

  defp fetch_user(id) do
    case Auth.get_user(id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  defp normalize_update_params(params) do
    Map.update(params, "active", false, &(&1 == "true"))
  end

  defp user_update_params(user) do
    %{
      "display_name" => user.display_name || "",
      "role" => user.role,
      "active" => to_string(user.active),
      "must_change_password" => to_string(user.must_change_password)
    }
  end

  defp prevent_self_target(socket, id, action) do
    if socket.assigns.current_user.id == id do
      {:error, {:self_target, action}}
    else
      :ok
    end
  end

  defp prevent_self_deactivation(socket, id, params) do
    if socket.assigns.current_user.id == id && Map.get(params, "active") == "false" do
      {:error, {:self_target, "disable"}}
    else
      :ok
    end
  end

  defp user_action_error(socket, {:error, :forbidden}) do
    {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
  end

  defp user_action_error(socket, {:error, :not_found}) do
    {:noreply, socket |> put_flash(:error, "User not found.") |> refresh_users()}
  end

  defp user_action_error(socket, {:error, {:self_target, action}}) do
    {:noreply, put_flash(socket, :error, "You cannot #{action} your own active session account.")}
  end

  defp user_action_error(socket, {:error, changeset}) do
    {:noreply, put_flash(socket, :error, changeset_error(changeset))}
  end

  defp user_action_error(socket, _error) do
    {:noreply, put_flash(socket, :error, "User action failed.")}
  end

  defp blank_to_nil(value) when is_binary(value) do
    value = String.trim(value)
    if value == "", do: nil, else: value
  end

  defp blank_to_nil(value), do: value

  defp changeset_error(changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.flat_map(fn {field, messages} ->
      Enum.map(messages, &"#{field} #{&1}")
    end)
    |> Enum.join("; ")
    |> then(fn
      "" -> "Validation failed."
      message -> message
    end)
  end

  defp status_class(%{active: true}), do: "bg-green-100 text-green-800"
  defp status_class(%{active: false}), do: "bg-red-100 text-red-800"

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">User Administration</h1>
          <p class="mt-1 text-sm text-gray-500">Manage local Config Manager accounts and roles.</p>
        </div>
        <div class="flex items-center gap-3 text-sm">
          <a href="/admin/roles" class="text-blue-600 hover:underline">Roles</a>
          <a href="/admin/api-tokens" class="text-blue-600 hover:underline">API Tokens</a>
        </div>
      </div>

      <%= if @reset_password do %>
        <section class="mb-6 rounded border border-yellow-300 bg-yellow-50 p-4 text-sm text-yellow-900">
          <div class="font-semibold">Temporary password for <%= @reset_password.username %></div>
          <code class="mt-2 block break-all rounded bg-white px-3 py-2 font-mono text-yellow-950">
            <%= @reset_password.password %>
          </code>
        </section>
      <% end %>

      <section class="mb-8 rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <h2 class="mb-4 text-lg font-semibold text-gray-900">Create User</h2>
        <form phx-submit="create_user" class="grid grid-cols-1 gap-4 md:grid-cols-6">
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="user[username]" placeholder="username" required />
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="user[display_name]" placeholder="display name" />
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="user[password]" type="password" placeholder="temporary password" required />
          <select class="rounded border border-gray-300 px-3 py-2 text-sm" name="user[role]">
            <%= for role <- @roles do %>
              <option value={role}><%= Policy.role_display_name(role) %></option>
            <% end %>
          </select>
          <select class="rounded border border-gray-300 px-3 py-2 text-sm" name="user[must_change_password]">
            <option value="true">Require password change</option>
            <option value="false">No forced change</option>
          </select>
          <button class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700" type="submit">
            Create User
          </button>
        </form>
      </section>

      <section class="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-gray-200 bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <th class="px-4 py-3 font-medium">User</th>
              <th class="px-4 py-3 font-medium">Role</th>
              <th class="px-4 py-3 font-medium">Status</th>
              <th class="px-4 py-3 font-medium">Update</th>
              <th class="px-4 py-3 font-medium">Password</th>
              <th class="px-4 py-3 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            <%= for user <- @users do %>
              <% form = Map.fetch!(@update_forms, user.id) %>
              <tr class="border-b border-gray-100 align-top last:border-0">
                <td class="px-4 py-3">
                  <div class="font-mono font-semibold text-gray-900"><%= user.username %></div>
                  <div class="text-xs text-gray-500"><%= user.display_name || "No display name" %></div>
                  <%= if user.must_change_password do %>
                    <span class="mt-1 inline-flex rounded bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">
                      password change required
                    </span>
                  <% end %>
                </td>
                <td class="px-4 py-3 text-gray-700"><%= Policy.role_display_name(user.role) %></td>
                <td class="px-4 py-3">
                  <span class={"inline-flex rounded px-2.5 py-0.5 text-xs font-medium #{status_class(user)}"}>
                    <%= if user.active, do: "active", else: "disabled" %>
                  </span>
                </td>
                <td class="px-4 py-3">
                  <form phx-submit="update_user" phx-value-id={user.id} class="space-y-2">
                    <input class="w-full rounded border border-gray-300 px-2 py-1.5 text-sm" name="user[display_name]" value={form[:display_name].value} />
                    <div class="grid grid-cols-2 gap-2">
                      <select class="rounded border border-gray-300 px-2 py-1.5 text-sm" name="user[role]">
                        <%= for role <- @roles do %>
                          <option value={role} selected={form[:role].value == role}>
                            <%= Policy.role_display_name(role) %>
                          </option>
                        <% end %>
                      </select>
                      <select class="rounded border border-gray-300 px-2 py-1.5 text-sm" name="user[active]">
                        <option value="true" selected={form[:active].value == "true"}>active</option>
                        <option value="false" selected={form[:active].value == "false"}>disabled</option>
                      </select>
                    </div>
                    <button class="rounded border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50" type="submit">
                      Save
                    </button>
                  </form>
                </td>
                <td class="px-4 py-3">
                  <form phx-submit="reset_password" phx-value-id={user.id} class="space-y-2">
                    <input class="w-full rounded border border-gray-300 px-2 py-1.5 text-sm" name="password" type="password" placeholder="blank generates one" />
                    <button class="rounded border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50" type="submit">
                      Reset
                    </button>
                  </form>
                </td>
                <td class="px-4 py-3">
                  <div class="flex flex-col gap-2">
                    <%= if user.active do %>
                      <button
                        phx-click="disable_user"
                        phx-value-id={user.id}
                        data-confirm="Disable this user and invalidate active sessions?"
                        class="rounded bg-yellow-100 px-3 py-1.5 text-xs font-medium text-yellow-800 hover:bg-yellow-200"
                      >
                        Disable
                      </button>
                    <% else %>
                      <button
                        phx-click="enable_user"
                        phx-value-id={user.id}
                        class="rounded bg-green-100 px-3 py-1.5 text-xs font-medium text-green-800 hover:bg-green-200"
                      >
                        Enable
                      </button>
                    <% end %>
                    <button
                      phx-click="delete_user"
                      phx-value-id={user.id}
                      data-confirm="Delete this user? This cannot be undone."
                      class="rounded bg-red-100 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-200"
                    >
                      Delete
                    </button>
                  </div>
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
