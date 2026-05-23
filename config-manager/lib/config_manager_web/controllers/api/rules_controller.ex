defmodule ConfigManagerWeb.Api.RulesController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Rules

  def index(conn, params) do
    result =
      Rules.list_rules(
        page: int_param(params, "page", 1),
        page_size: int_param(params, "page_size", 25),
        search: params["search"],
        category: params["category"],
        repository_id: params["repository_id"],
        sort_by: params["sort_by"],
        sort_dir: params["sort_dir"]
      )

    json(conn, %{
      data: Enum.map(result.entries, &rule_json/1),
      meta: Map.take(result, [:page, :page_size, :total_count, :total_pages])
    })
  end

  def create(conn, params) do
    case Rules.create_rule(params, current_actor(conn)) do
      {:ok, rule} ->
        conn
        |> put_status(:created)
        |> json(%{data: rule_json(rule)})

      {:error, changeset = %Ecto.Changeset{}} ->
        changeset_error(conn, changeset)

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  def deploy(conn, %{"pool_id" => pool_id} = params) do
    opts = [start_task?: bool_param(params, "start_task", true)]

    case Rules.deploy_ruleset_to_pool(pool_id, current_actor(conn), opts) do
      {:ok, result} ->
        json(conn, %{data: result})

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  def deploy(conn, _params) do
    api_error(conn, :unprocessable_entity, "VALIDATION_FAILED", "pool_id is required")
  end

  defp rule_json(rule) do
    %{
      id: rule.id,
      sid: rule.sid,
      message: rule.message,
      category: rule.category,
      classtype: rule.classtype,
      severity: rule.severity,
      revision: rule.revision,
      enabled: rule.enabled,
      repository_id: rule.repository_id,
      repository_name: rule.repository_name,
      inserted_at: rule.inserted_at,
      updated_at: rule.updated_at
    }
  end
end
