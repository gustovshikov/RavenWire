defmodule ConfigManagerWeb.AuthHelpers do
  @moduledoc "LiveView authentication and RBAC hooks."

  import Phoenix.Component
  import Phoenix.LiveView

  alias ConfigManager.Auth
  alias ConfigManager.Auth.Policy
  alias ConfigManager.Audit

  def on_mount(:require_auth, _params, session, socket) do
    case Auth.validate_session(session["session_token"]) do
      {:ok, user} -> {:cont, assign(socket, :current_user, user)}
      {:error, _reason} -> {:halt, redirect(socket, to: "/login")}
    end
  end

  def on_mount({:require_permission, permission}, _params, _session, socket) do
    user = socket.assigns[:current_user]

    if user && Policy.has_permission?(user.role, permission) do
      {:cont, socket}
    else
      {:halt, socket |> put_flash(:error, "Insufficient permissions.") |> redirect(to: "/")}
    end
  end

  def authorize(socket, permission, action \\ nil) do
    user = socket.assigns[:current_user]

    if user && Policy.has_permission?(user.role, permission) do
      :ok
    else
      if action do
        Audit.log(%{
          actor: (user && user.username) || "anonymous",
          actor_type: if(user, do: "user", else: "anonymous"),
          action: "permission_denied",
          target_type: "live_event",
          target_id: to_string(action),
          result: "failure",
          detail: %{
            required_permission: permission,
            action: to_string(action),
            event_or_route: to_string(action)
          }
        })
      end

      {:error, :forbidden}
    end
  end
end
