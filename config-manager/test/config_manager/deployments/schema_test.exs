defmodule ConfigManager.Deployments.SchemaTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Deployments.{Deployment, DeploymentResult}
  alias ConfigManager.SensorPod

  test "deployment create changeset validates required fields and operator type" do
    valid =
      Deployment.create_changeset(%Deployment{}, %{
        pool_id: Ecto.UUID.generate(),
        operator: "operator",
        operator_type: "user",
        config_version: 1,
        config_snapshot: %{"capture" => %{"version" => 1}}
      })

    assert valid.valid?

    invalid =
      Deployment.create_changeset(%Deployment{}, %{
        pool_id: Ecto.UUID.generate(),
        operator: "operator",
        operator_type: "robot",
        config_version: 0,
        config_snapshot: "not a map"
      })

    refute invalid.valid?
    assert %{operator_type: [_], config_version: [_], config_snapshot: [_]} = errors_on(invalid)
  end

  test "deployment status changeset enforces valid transitions" do
    deployment = %Deployment{status: "pending"}

    assert Deployment.status_changeset(deployment, "validating").valid?
    refute Deployment.status_changeset(deployment, "deploying").valid?

    successful = %Deployment{status: "successful"}
    assert Deployment.status_changeset(successful, "rolled_back").valid?
    refute Deployment.status_changeset(successful, "deploying").valid?
  end

  test "deployment result changesets validate status and truncate messages" do
    long_message = String.duplicate("a", DeploymentResult.message_limit() + 10)

    changeset =
      DeploymentResult.create_changeset(%DeploymentResult{}, %{
        deployment_id: Ecto.UUID.generate(),
        sensor_pod_id: Ecto.UUID.generate(),
        status: "failed",
        message: long_message
      })

    assert changeset.valid?

    assert changeset.changes.message ==
             String.slice(long_message, 0, DeploymentResult.message_limit())

    invalid =
      DeploymentResult.update_changeset(%DeploymentResult{}, %{
        status: "exploded"
      })

    refute invalid.valid?
    assert %{status: [_]} = errors_on(invalid)
  end

  test "sensor pod deployment success changeset records deployed versions" do
    deployment = %{
      id: Ecto.UUID.generate(),
      config_version: 3,
      forwarding_config_version: 2,
      bpf_version: 1
    }

    changeset = SensorPod.deployment_success_changeset(%SensorPod{}, deployment)

    assert changeset.valid?
    assert changeset.changes.last_deployment_id == deployment.id
    assert changeset.changes.last_deployed_config_version == 3
    assert changeset.changes.last_deployed_forwarding_version == 2
    assert changeset.changes.last_deployed_bpf_version == 1
    assert %DateTime{} = changeset.changes.last_deployed_at
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
