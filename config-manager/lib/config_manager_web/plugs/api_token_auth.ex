defmodule ConfigManagerWeb.Plugs.ApiTokenAuth do
  @moduledoc "Authenticates Public API requests with scoped bearer tokens."

  import Plug.Conn
  import Phoenix.Controller

  alias ConfigManager.Auth
  alias ConfigManagerWeb.Api.Errors

  def init(opts), do: opts

  def call(conn, _opts) do
    conn
    |> bearer_token()
    |> case do
      nil ->
        unauthorized(conn)

      raw_token ->
        case Auth.authenticate_api_token(raw_token) do
          {:ok, token} ->
            conn
            |> assign(:current_token, token)
            |> assign(:current_user, token.user)

          {:error, :invalid} ->
            unauthorized(conn)
        end
    end
  end

  defp bearer_token(conn) do
    conn
    |> get_req_header("authorization")
    |> List.first()
    |> parse_bearer()
  end

  defp parse_bearer("Bearer " <> token), do: String.trim(token)
  defp parse_bearer("bearer " <> token), do: String.trim(token)
  defp parse_bearer(_header), do: nil

  defp unauthorized(conn) do
    conn
    |> put_status(:unauthorized)
    |> json(Errors.body(conn, "UNAUTHORIZED", "Invalid or missing bearer token"))
    |> halt()
  end
end
