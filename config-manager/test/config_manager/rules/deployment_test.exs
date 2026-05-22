defmodule ConfigManager.Rules.DeploymentTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Rules
  alias ConfigManager.Rules.{PoolRulesetAssignment, SuricataRule}
  alias ConfigManager.{AuditEntry, Repo, SensorPod, SensorPool}

  defmodule SuccessfulDeployer do
    import Ecto.Query

    alias ConfigManager.{Repo, SensorPod}

    def deploy_to_pool(pool_id, rule_files, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:rule_files_deployed, rule_files, opts})

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

  test "assign_ruleset_to_pool creates assignment and query helpers return it" do
    pool = insert_pool!("assign-pool")
    ruleset = insert_ruleset!("assign-ruleset")

    assert {:ok, assignment} = Rules.assign_ruleset_to_pool(ruleset, pool, "tester")
    assert assignment.pool_id == pool.id
    assert assignment.ruleset_id == ruleset.id
    assert assignment.assigned_by == "tester"

    assert Rules.pool_assignment(pool.id).id == assignment.id
    assert Rules.pool_ruleset(pool.id).id == ruleset.id

    audit = Repo.get_by!(AuditEntry, action: "ruleset_assigned_to_pool", target_id: pool.id)
    assert audit.detail =~ ruleset.name
  end

  test "assign_ruleset_to_pool replaces existing assignment and clears deployed version" do
    pool = insert_pool!("replace-pool")
    first = insert_ruleset!("first-ruleset")
    second = insert_ruleset!("second-ruleset")

    assert {:ok, assignment} = Rules.assign_ruleset_to_pool(first, pool, "tester")

    assignment
    |> PoolRulesetAssignment.changeset(%{deployed_rule_version: 4})
    |> Repo.update!()

    assert {:ok, replaced} = Rules.assign_ruleset_to_pool(second, pool, "tester")
    assert replaced.id == assignment.id
    assert replaced.ruleset_id == second.id
    assert replaced.deployed_rule_version == nil

    assert Repo.aggregate(PoolRulesetAssignment, :count, :id) == 1
  end

  test "unassign_ruleset_from_pool deletes assignment and audits" do
    pool = insert_pool!("unassign-pool")
    ruleset = insert_ruleset!("unassign-ruleset")
    {:ok, assignment} = Rules.assign_ruleset_to_pool(ruleset, pool, "tester")

    assert {:ok, deleted} = Rules.unassign_ruleset_from_pool(pool, "tester")
    assert deleted.id == assignment.id
    assert Rules.pool_assignment(pool.id) == nil
    assert Repo.get_by!(AuditEntry, action: "ruleset_unassigned_from_pool", target_id: pool.id)
  end

  test "unassign_ruleset_from_pool returns no_assignment when pool has none" do
    pool = insert_pool!("empty-unassign-pool")

    assert {:error, :no_assignment} = Rules.unassign_ruleset_from_pool(pool, "tester")
  end

  test "deploy_ruleset_to_pool compiles, deploys, updates versions, broadcasts, and audits" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rulesets")
    pool = insert_pool!("deploy-rules-pool")
    sensor = insert_sensor!("deploy-rules-sensor", pool.id)
    rule = insert_rule!(%{sid: 900_001, category: "malware"})
    ruleset = insert_ruleset!("deploy-ruleset", categories: ["malware"])
    {:ok, _assignment} = Rules.assign_ruleset_to_pool(ruleset, pool, "tester")

    assert {:ok, %{results: [%{pod_id: pod_id}], version: version}} =
             Rules.deploy_ruleset_to_pool(pool.id, "tester",
               deployer: SuccessfulDeployer,
               test_pid: self()
             )

    assert pod_id == sensor.id
    assert version == ruleset.version

    assert_received {:rule_files_deployed, %{"malware.rules" => content}, deploy_opts}
    assert content =~ "sid:#{rule.sid};"
    assert deploy_opts[:version] == ruleset.version
    assert deploy_opts[:updated_by] == "tester"

    assert Repo.get!(SensorPod, sensor.id).last_deployed_rule_version == ruleset.version
    assert Rules.deployed_rule_version(pool.id) == ruleset.version

    audit = Repo.get_by!(AuditEntry, action: "rules_deployed", target_id: pool.id)
    assert audit.detail =~ ruleset.name

    assert %{entries: [^audit], total_count: 1} = Rules.list_rule_deployments()
    assert %{entries: [^audit], total_count: 1} = Rules.list_pool_rule_deployments(pool.id)
    assert_received {:rules_deployed, pool_id, deployed_version}
    assert pool_id == pool.id
    assert deployed_version == ruleset.version
  end

  test "deploy_ruleset_to_pool returns error when pool has no assignment" do
    pool = insert_pool!("no-assignment-pool")

    assert {:error, :no_assignment} = Rules.deploy_ruleset_to_pool(pool.id, "tester")
  end

  test "out_of_sync_count and sensor_sync_statuses classify mixed rule versions" do
    pool = insert_pool!("sync-pool")
    ruleset = insert_ruleset!("sync-ruleset")
    {:ok, assignment} = Rules.assign_ruleset_to_pool(ruleset, pool, "tester")

    in_sync = insert_sensor!("sync-in", pool.id, ruleset.version)
    never = insert_sensor!("sync-never", pool.id, nil)
    stale = insert_sensor!("sync-stale", pool.id, ruleset.version + 1)

    assert Rules.out_of_sync_count(pool.id) == 2

    statuses =
      Rules.sensor_sync_statuses(pool.id) |> Map.new(fn status -> {status.sensor.id, status} end)

    assert statuses[in_sync.id].status == :in_sync
    assert statuses[in_sync.id].expected_version == ruleset.version
    assert statuses[never.id].status == :out_of_sync
    assert statuses[never.id].deployed_version == nil
    assert statuses[stale.id].status == :out_of_sync

    assert assignment.id == Rules.pool_assignment(pool.id).id
  end

  test "sync status handles pools with no assigned ruleset" do
    pool = insert_pool!("no-ruleset-status-pool")
    sensor = insert_sensor!("no-ruleset-status-sensor", pool.id)

    assert Rules.out_of_sync_count(pool.id) == 0
    assert [status] = Rules.sensor_sync_statuses(pool.id)
    assert status.sensor.id == sensor.id
    assert status.status == :no_ruleset_assigned
    assert status.expected_version == nil
    refute status.in_sync
  end

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "tester")
    |> Repo.insert!()
  end

  defp insert_ruleset!(name, opts \\ []) do
    {:ok, ruleset} =
      Rules.create_ruleset(
        %{name: name, categories: Keyword.get(opts, :categories, [])},
        "tester"
      )

    ruleset
  end

  defp insert_rule!(attrs) do
    sid = Map.fetch!(attrs, :sid)
    message = Map.get(attrs, :message, "Rule #{sid}")
    revision = Map.get(attrs, :revision, 1)

    attrs =
      Map.merge(
        %{
          message: message,
          raw_text:
            ~s|alert ip any any -> any any (msg:"#{message}"; classtype:trojan-activity; sid:#{sid}; rev:#{revision};)|,
          category: "local",
          classtype: "trojan-activity",
          severity: 2,
          revision: revision,
          enabled: true
        },
        attrs
      )

    %SuricataRule{}
    |> SuricataRule.changeset(attrs)
    |> Repo.insert!()
  end

  defp insert_sensor!(name, pool_id, last_deployed_rule_version \\ nil) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(
      status: "enrolled",
      pool_id: pool_id,
      last_deployed_rule_version: last_deployed_rule_version
    )
    |> Repo.update!()
  end
end
