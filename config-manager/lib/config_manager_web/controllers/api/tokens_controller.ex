defmodule ConfigManagerWeb.Api.TokensController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Auth
  alias ConfigManager.Auth.ApiToken

  def create(conn, params) do
    user = conn.assigns.current_user

    case Auth.create_api_token(user, params, current_actor(conn)) do
      {:ok, token, raw_token} ->
        conn
        |> put_status(:created)
        |> json(%{data: token_json(token), token: raw_token})

      {:error, changeset = %Ecto.Changeset{}} ->
        changeset_error(conn, changeset)

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  defp token_json(%ApiToken{} = token) do
    %{
      id: token.id,
      name: token.name,
      user_id: token.user_id,
      permissions: ApiToken.permissions_list(token),
      expires_at: token.expires_at,
      revoked_at: token.revoked_at,
      inserted_at: token.inserted_at,
      updated_at: token.updated_at
    }
  end
end
