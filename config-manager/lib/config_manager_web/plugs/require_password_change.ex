defmodule ConfigManagerWeb.Plugs.RequirePasswordChange do
  @moduledoc "Redirects users with forced password changes to the password change flow."

  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    user = conn.assigns[:current_user]

    if user && user.must_change_password && not allowed_path?(conn.request_path) do
      conn
      |> put_flash(:error, "You must change your password before continuing.")
      |> redirect(to: "/password/change")
      |> halt()
    else
      conn
    end
  end

  defp allowed_path?("/password/change"), do: true
  defp allowed_path?("/logout"), do: true
  defp allowed_path?(_path), do: false
end
