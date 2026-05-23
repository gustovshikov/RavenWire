defmodule ConfigManagerWeb.Api.UsersController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Auth

  def create(conn, params) do
    case Auth.create_user(params, current_actor(conn)) do
      {:ok, user} ->
        conn
        |> put_status(:created)
        |> json(%{data: user_json(user)})

      {:error, changeset = %Ecto.Changeset{}} ->
        changeset_error(conn, changeset)

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  defp user_json(user) do
    %{
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      role: user.role,
      active: user.active,
      must_change_password: user.must_change_password,
      inserted_at: user.inserted_at,
      updated_at: user.updated_at
    }
  end
end
