defmodule ConfigManagerWeb.AuthHelpers do
  @moduledoc "LiveView authentication and RBAC hooks."

  import Phoenix.Component
  import Phoenix.LiveView

  alias ConfigManager.Auth
  alias ConfigManager.Auth.Policy

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

  def authorize(socket, permission) do
    user = socket.assigns[:current_user]

    if user && Policy.has_permission?(user.role, permission) do
      :ok
    else
      {:error, :forbidden}
    end
  end
end
