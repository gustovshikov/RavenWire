defmodule ConfigManager.Deployments.SchemaPropertyTest do
  @moduledoc "Property coverage for deployment schema status validation and result messages."

  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Deployments.{Deployment, DeploymentResult}

  property "Property 13: deployment and result status changesets accept only valid statuses",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 500) do
      deployment_status = status_sample(code, Deployment.statuses())
      result_status = status_sample(code, DeploymentResult.statuses())

      deployment_changeset =
        Deployment.create_changeset(%Deployment{}, %{
          pool_id: Ecto.UUID.generate(),
          status: deployment_status,
          operator: "property-operator",
          operator_type: "user",
          config_version: 1,
          config_snapshot: %{"capture" => %{"version" => 1}}
        })

      result_changeset =
        DeploymentResult.create_changeset(%DeploymentResult{}, %{
          deployment_id: Ecto.UUID.generate(),
          sensor_pod_id: Ecto.UUID.generate(),
          status: result_status
        })

      deployment_changeset.valid? == deployment_status in Deployment.statuses() and
        result_changeset.valid? == result_status in DeploymentResult.statuses()
    end
  end

  property "Property 14: deployment status transitions follow the valid transition map",
           [:verbose, numtests: 120] do
    forall code <- integer(0, transition_space_size() - 1) do
      statuses = Deployment.statuses()
      current = Enum.at(statuses, div(code, length(statuses)))
      next = Enum.at(statuses, rem(code, length(statuses)))

      changeset = Deployment.status_changeset(%Deployment{status: current}, next)

      expected_valid? =
        next == current or next in Map.get(Deployment.valid_transitions(), current, [])

      changeset.valid? == expected_valid?
    end
  end

  property "Property 15: deployment result messages are truncated to the schema limit",
           [:verbose, numtests: 60] do
    forall length <- integer(1, DeploymentResult.message_limit() * 2) do
      message = String.duplicate("m", length)
      expected = String.slice(message, 0, DeploymentResult.message_limit())

      create_changeset =
        DeploymentResult.create_changeset(%DeploymentResult{}, %{
          deployment_id: Ecto.UUID.generate(),
          sensor_pod_id: Ecto.UUID.generate(),
          status: "failed",
          message: message
        })

      update_changeset =
        DeploymentResult.update_changeset(%DeploymentResult{}, %{
          status: "failed",
          message: message
        })

      create_changeset.changes.message == expected and
        update_changeset.changes.message == expected
    end
  end

  defp status_sample(code, valid_statuses) do
    if rem(code, 3) == 0 do
      Enum.at(valid_statuses, rem(div(code, 3), length(valid_statuses)))
    else
      "invalid-status-#{code}"
    end
  end

  defp transition_space_size, do: length(Deployment.statuses()) * length(Deployment.statuses())
end
