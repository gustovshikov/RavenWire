defmodule ConfigManagerWeb.Api.RulesetsController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Rules

  def index(conn, _params) do
    json(conn, %{data: Enum.map(Rules.list_rulesets(), &ruleset_summary_json/1)})
  end

  def create(conn, params) do
    case Rules.create_ruleset(params, current_actor(conn)) do
      {:ok, ruleset} ->
        conn
        |> put_status(:created)
        |> json(%{data: ruleset_json(ruleset)})

      {:error, changeset = %Ecto.Changeset{}} ->
        changeset_error(conn, changeset)

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  defp ruleset_summary_json(%{ruleset: ruleset, effective_count: count, pool_count: pool_count}) do
    ruleset
    |> ruleset_json()
    |> Map.merge(%{effective_count: count, pool_count: pool_count})
  end

  defp ruleset_json(ruleset) do
    %{
      id: ruleset.id,
      name: ruleset.name,
      description: ruleset.description,
      version: ruleset.version,
      categories: ruleset.categories || [],
      updated_by: ruleset.updated_by,
      inserted_at: ruleset.inserted_at,
      updated_at: ruleset.updated_at
    }
  end
end
