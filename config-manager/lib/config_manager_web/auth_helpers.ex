defmodule ConfigManagerWeb.AuthHelpers do
  @moduledoc "LiveView authentication and RBAC hooks."

  import Phoenix.Component
  import Phoenix.LiveView

  alias ConfigManager.{Alerts, Auth}
  alias ConfigManager.Auth.Policy
  alias ConfigManager.Audit

  def on_mount(:require_auth, _params, session, socket) do
    case Auth.validate_session(session["session_token"]) do
      {:ok, user} ->
        if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "alerts")

        socket =
          socket
          |> assign(:current_user, user)
          |> assign(:firing_alert_count, Alerts.firing_alert_count())
          |> attach_hook(:alert_nav_badge, :handle_info, fn
            {event, _alert}, socket
            when event in [:alert_fired, :alert_updated, :alert_resolved] ->
              {:cont, assign(socket, :firing_alert_count, Alerts.firing_alert_count())}

            _message, socket ->
              {:cont, socket}
          end)

        {:cont, socket}

      {:error, _reason} ->
        {:halt, redirect(socket, to: "/login")}
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
