defmodule ConfigManagerWeb.Api.DeploymentsController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Deployments

  def index(conn, params) do
    result =
      Deployments.list_deployments(
        page: int_param(params, "page", 1),
        page_size: int_param(params, "page_size", 25),
        pool_id: params["pool_id"],
        status: params["status"],
        operator: params["operator"]
      )

    json(conn, %{
      data: Enum.map(result.entries, &deployment_json/1),
      meta: Map.take(result, [:page, :page_size, :total_count])
    })
  end

  def show(conn, %{"id" => id}) do
    case Deployments.get_deployment(id) do
      nil -> not_found(conn, "Deployment")
      deployment -> json(conn, %{data: deployment_json(deployment)})
    end
  end

  def create(conn, %{"pool_id" => pool_id} = params) do
    opts = [start_orchestrator?: bool_param(params, "start_orchestrator", true)]

    case Deployments.create_deployment(pool_id, current_actor(conn), opts) do
      {:ok, deployment} ->
        conn
        |> put_status(:created)
        |> json(%{data: deployment_json(deployment)})

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  def create(conn, _params) do
    api_error(conn, :unprocessable_entity, "VALIDATION_FAILED", "pool_id is required")
  end

  def cancel(conn, %{"id" => id}) do
    case Deployments.get_deployment(id) do
      nil ->
        not_found(conn, "Deployment")

      deployment ->
        case Deployments.cancel_deployment(deployment, current_actor(conn)) do
          {:ok, cancelled} -> json(conn, %{data: deployment_json(cancelled)})
          {:error, reason} -> action_error(conn, reason)
        end
    end
  end

  def rollback(conn, %{"id" => id}) do
    case Deployments.get_deployment(id) do
      nil ->
        not_found(conn, "Deployment")

      deployment ->
        case Deployments.rollback_deployment(deployment, current_actor(conn)) do
          {:ok, rollback} -> json(conn, %{data: deployment_json(rollback)})
          {:error, reason} -> action_error(conn, reason)
        end
    end
  end

  defp deployment_json(deployment) do
    %{
      id: deployment.id,
      pool_id: deployment.pool_id,
      status: deployment.status,
      operator: deployment.operator,
      operator_type: deployment.operator_type,
      config_version: deployment.config_version,
      forwarding_config_version: deployment.forwarding_config_version,
      bpf_version: deployment.bpf_version,
      diff_summary: deployment.diff_summary,
      rollback_of_deployment_id: deployment.rollback_of_deployment_id,
      source_deployment_id: deployment.source_deployment_id,
      started_at: deployment.started_at,
      completed_at: deployment.completed_at,
      failure_reason: deployment.failure_reason,
      inserted_at: deployment.inserted_at,
      updated_at: deployment.updated_at
    }
  end
end
