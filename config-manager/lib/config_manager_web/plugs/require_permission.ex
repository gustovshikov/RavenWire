defmodule ConfigManagerWeb.Plugs.RequirePermission do
  @moduledoc "Requires the current user to have a specific RBAC permission."

  import Plug.Conn
  import Phoenix.Controller

  alias ConfigManager.Audit
  alias ConfigManager.Auth.{ApiToken, Policy}

  def init(permission), do: permission

  def call(conn, permission) do
    token = conn.assigns[:current_token]
    user = conn.assigns[:current_user]

    cond do
      token && token_has_permission?(token, permission) ->
        conn

      is_nil(token) && user && Policy.has_permission?(user.role, permission) ->
        conn

      true ->
        Audit.log(%{
          actor: actor_name(token, user),
          actor_type: actor_type(token, user),
          action: "permission_denied",
          target_type: "route",
          target_id: conn.request_path,
          result: "failure",
          detail: %{required_permission: permission, route: conn.request_path}
        })

        forbidden(conn)
    end
  end

  defp token_has_permission?(token, "alerts:view") do
    "sensors:view" in ApiToken.permissions_list(token)
  end

  defp token_has_permission?(token, permission) do
    permission in ApiToken.permissions_list(token)
  end

  defp forbidden(conn) do
    if api_request?(conn) do
      conn
      |> put_status(:forbidden)
      |> json(%{error: %{code: "FORBIDDEN", message: "Insufficient permissions"}})
      |> halt()
    else
      conn
      |> put_status(:forbidden)
      |> put_view(html: ConfigManagerWeb.ErrorHTML)
      |> render(:"403")
      |> halt()
    end
  end

  defp api_request?(conn) do
    String.starts_with?(conn.request_path || "", "/api/")
  end

  defp actor_name(%{name: name}, _user), do: name
  defp actor_name(_token, %{username: username}), do: username
  defp actor_name(_token, _user), do: "anonymous"

  defp actor_type(%{id: _id}, _user), do: "api_token"
  defp actor_type(_token, %{id: _id}), do: "user"
  defp actor_type(_token, _user), do: "anonymous"
end
