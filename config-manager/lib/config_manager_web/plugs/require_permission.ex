defmodule ConfigManagerWeb.Plugs.RequirePermission do
  @moduledoc "Requires the current user to have a specific RBAC permission."

  import Plug.Conn
  import Phoenix.Controller

  alias ConfigManager.Audit
  alias ConfigManager.Auth.Policy

  def init(permission), do: permission

  def call(conn, permission) do
    user = conn.assigns[:current_user]

    if user && Policy.has_permission?(user.role, permission) do
      conn
    else
      Audit.log(%{
        actor: if(user, do: user.username, else: "anonymous"),
        actor_type: if(user, do: "user", else: "anonymous"),
        action: "permission_denied",
        target_type: "route",
        target_id: conn.request_path,
        result: "failure",
        detail: %{required_permission: permission, route: conn.request_path}
      })

      conn
      |> put_status(:forbidden)
      |> put_view(html: ConfigManagerWeb.ErrorHTML)
      |> render(:"403")
      |> halt()
    end
  end
end
