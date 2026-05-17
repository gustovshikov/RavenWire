defmodule ConfigManager.RuleDeployerTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.{Repo, RuleDeployer, SensorPod, SensorPool}

  test "deploy_to_pod returns not found for unknown pod" do
    assert {:error, :pod_not_found} =
             RuleDeployer.deploy_to_pod(Ecto.UUID.generate(), %{
               "local.rules" => "alert tcp any any -> any any (sid:1;)"
             })
  end

  test "deploy_to_pod delegates enrolled pod and reports missing control API host" do
    pod = insert_sensor!("rule-pod", "enrolled")

    assert {:error, :no_control_api_host} =
             RuleDeployer.deploy_to_pod(pod.id, %{
               "local.rules" => "alert tcp any any -> any any (sid:1;)"
             })
  end

  test "deploy_to_pool targets only enrolled pods in the requested pool" do
    pool = insert_pool!("rules-pool")
    enrolled = insert_sensor!("rules-enrolled", "enrolled", pool.id)
    _pending = insert_sensor!("rules-pending", "pending", pool.id)
    _other_pool = insert_sensor!("rules-other", "enrolled", insert_pool!("other-pool").id)

    assert {:ok,
            [
              %{
                pod_id: pod_id,
                pod_name: "rules-enrolled",
                result: {:error, :no_control_api_host}
              }
            ]} =
             RuleDeployer.deploy_to_pool(pool.id, %{
               "local.rules" => "alert tcp any any -> any any (sid:1;)"
             })

    assert pod_id == enrolled.id
  end

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "tester")
    |> Repo.insert!()
  end

  defp insert_sensor!(name, status, pool_id \\ nil) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: status, pool_id: pool_id)
    |> Repo.update!()
  end
end
