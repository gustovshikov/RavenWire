defmodule ConfigManagerWeb.Api.RepositoriesController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Rules

  def index(conn, _params) do
    json(conn, %{data: Enum.map(Rules.list_repositories(), &repository_json/1)})
  end

  def create(conn, params) do
    case Rules.create_repository(params, current_actor(conn)) do
      {:ok, repository} ->
        conn
        |> put_status(:created)
        |> json(%{data: repository_json(repository)})

      {:error, changeset = %Ecto.Changeset{}} ->
        changeset_error(conn, changeset)

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  defp repository_json(repository) do
    %{
      id: repository.id,
      name: repository.name,
      url: repository.url,
      repo_type: repository.repo_type,
      last_updated_at: repository.last_updated_at,
      last_update_status: repository.last_update_status,
      last_update_error: repository.last_update_error,
      rule_count: repository.rule_count,
      inserted_at: repository.inserted_at,
      updated_at: repository.updated_at
    }
  end
end
