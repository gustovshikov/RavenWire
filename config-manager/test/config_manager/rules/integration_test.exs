defmodule ConfigManager.Rules.IntegrationTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Rules
  alias ConfigManager.{AuditEntry, Repo, SensorPod, SensorPool}

  defmodule LifecycleFetcher do
    def fetch_and_parse(_url) do
      if pid = Process.whereis(:rules_lifecycle_test) do
        send(pid, :repository_fetch_started)
      end

      {:ok,
       [
         %{
           sid: 940_001,
           message: "Lifecycle malware",
           raw_text:
             ~s|alert ip any any -> any any (msg:"Lifecycle malware"; classtype:trojan-activity; sid:940001; rev:1;)|,
           category: "malware",
           classtype: "trojan-activity",
           revision: 1,
           severity: 2,
           enabled: true
         }
       ]}
    end
  end

  defmodule LifecycleDeployer do
    import Ecto.Query

    alias ConfigManager.{Repo, SensorPod}

    def deploy_to_pool(pool_id, rule_files, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:lifecycle_deployed, rule_files, opts})

      results =
        Repo.all(
          from(p in SensorPod,
            where: p.pool_id == ^pool_id and p.status == "enrolled",
            order_by: [asc: p.name]
          )
        )
        |> Enum.map(fn pod ->
          %{pod_id: pod.id, pod_name: pod.name, result: {:ok, %{"status" => "ok"}}}
        end)

      {:ok, results}
    end
  end

  test "full rule lifecycle imports, composes, assigns, deploys, syncs, and audits" do
    Process.register(self(), :rules_lifecycle_test)

    on_exit(fn ->
      if Process.whereis(:rules_lifecycle_test), do: Process.unregister(:rules_lifecycle_test)
    end)

    assert {:ok, repository} =
             Rules.create_repository(
               %{
                 name: "Lifecycle Feed",
                 url: "https://example.test/lifecycle.tar.gz",
                 repo_type: "custom"
               },
               "operator"
             )

    assert {:ok, :updating} =
             Rules.update_repository(repository, "operator", fetcher: LifecycleFetcher)

    assert_receive :repository_fetch_started

    assert wait_until(fn ->
             Rules.get_repository(repository.id).last_update_status == "success"
           end)

    imported_rule = Rules.get_rule_by_sid(940_001)
    assert imported_rule.message == "Lifecycle malware"
    assert imported_rule.repository_name == "Lifecycle Feed"

    assert {:ok, ruleset} =
             Rules.create_ruleset(
               %{name: "lifecycle-rules", categories: ["malware"]},
               "operator"
             )

    assert Rules.effective_rule_count(ruleset.id) == 1

    pool = insert_pool!("lifecycle-pool")
    sensor = insert_sensor!("lifecycle-sensor", pool.id)

    assert {:ok, _assignment} = Rules.assign_ruleset_to_pool(ruleset, pool, "operator")

    assert {:ok, %{version: version}} =
             Rules.deploy_ruleset_to_pool(pool.id, "operator",
               deployer: LifecycleDeployer,
               test_pid: self()
             )

    assert_receive {:lifecycle_deployed, %{"malware.rules" => content}, deploy_opts}
    assert content =~ "sid:940001;"
    assert deploy_opts[:version] == version

    assert Repo.get!(SensorPod, sensor.id).last_deployed_rule_version == version
    assert Rules.deployed_rule_version(pool.id) == version
    assert Rules.out_of_sync_count(pool.id) == 0
    assert [%{status: :in_sync}] = Rules.sensor_sync_statuses(pool.id)

    for action <- [
          "repository_added",
          "repository_updated",
          "ruleset_created",
          "ruleset_assigned_to_pool",
          "rules_deployed"
        ] do
      assert Repo.get_by(AuditEntry, action: action)
    end
  end

  defp wait_until(fun, attempts \\ 20)

  defp wait_until(fun, attempts) when attempts > 0 do
    if fun.() do
      true
    else
      Process.sleep(10)
      wait_until(fun, attempts - 1)
    end
  end

  defp wait_until(_fun, 0), do: false

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "operator")
    |> Repo.insert!()
  end

  defp insert_sensor!(name, pool_id) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "operator"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end
end
