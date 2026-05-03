defmodule ConfigManagerWeb.Plugs.RequireAuth do
  @moduledoc "Requires a valid RavenWire browser session."

  import Plug.Conn
  import Phoenix.Controller

  alias ConfigManager.Auth

  def init(opts), do: opts

  def call(conn, _opts) do
    token = get_session(conn, :session_token)

    case Auth.validate_session(token) do
      {:ok, user} ->
        assign(conn, :current_user, user)

      {:error, :expired} ->
        conn
        |> configure_session(drop: true)
        |> put_flash(:error, "Session expired. Please log in again.")
        |> redirect(to: "/login")
        |> halt()

      {:error, _reason} ->
        conn
        |> configure_session(drop: true)
        |> redirect(to: "/login")
        |> halt()
    end
  end
end
