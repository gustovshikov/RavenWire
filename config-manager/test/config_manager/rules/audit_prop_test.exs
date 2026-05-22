defmodule ConfigManager.Rules.AuditPropTest do
  @moduledoc "Property coverage for audit entry completeness on rule store mutations."

  use ExUnit.Case, async: false
  use PropCheck

  import Ecto.Query

  alias ConfigManager.Rules

  alias ConfigManager.Rules.{
    PoolRulesetAssignment,
    RuleRepository,
    Ruleset,
    RulesetRule,
    SuricataRule
  }

  alias ConfigManager.{AuditEntry, Repo, SensorPod, SensorPool}

  defmodule AuditPropDeployer do
    import Ecto.Query

    alias ConfigManager.{Repo, SensorPod}

    def deploy_to_pool(pool_id, _rule_files, _opts) do
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

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  property "Property 12: Every rule store mutation produces an audit entry",
           [:verbose, numtests: 20] do
    forall code <- integer(1, 100_000) do
      reset_rule_store!()

      actor = "audit-property"
      rule = insert_rule!(950_000 + code, "audit-category-#{code}")

      {:ok, _rule} = Rules.toggle_rule(rule, actor)
      {:ok, _count} = Rules.toggle_category(rule.category, false, actor)
      {:ok, _count} = Rules.toggle_category(rule.category, true, actor)

      {:ok, repository} =
        Rules.create_repository(
          %{
            name: "audit-repo-#{code}",
            url: "https://example.test/audit-#{code}.tar.gz",
            repo_type: "custom"
          },
          actor
        )

      {:ok, _deleted_repository} = Rules.delete_repository(repository, actor)

      {:ok, ruleset} =
        Rules.create_ruleset(
          %{name: "audit-ruleset-#{code}", categories: [rule.category]},
          actor
        )

      {:ok, updated_ruleset} =
        Rules.update_ruleset(ruleset, %{categories: [rule.category, "other-#{code}"]}, actor)

      {:ok, _override} = Rules.add_ruleset_override(updated_ruleset, rule.sid, "include", actor)
      ruleset_with_override = Rules.get_ruleset(updated_ruleset.id)
      {:ok, _removed} = Rules.remove_ruleset_override(ruleset_with_override, rule.sid, actor)

      pool = insert_pool!("audit-pool-#{code}")
      _sensor = insert_sensor!("audit-sensor-#{code}", pool.id)
      ruleset_for_assignment = Rules.get_ruleset(updated_ruleset.id)

      {:ok, _assignment} = Rules.assign_ruleset_to_pool(ruleset_for_assignment, pool, actor)

      {:ok, %{version: _version}} =
        Rules.deploy_ruleset_to_pool(pool.id, actor, deployer: AuditPropDeployer)

      {:ok, _unassigned} = Rules.unassign_ruleset_from_pool(pool, actor)
      {:ok, _deleted_ruleset} = Rules.delete_ruleset(Rules.get_ruleset(updated_ruleset.id), actor)

      Enum.all?(
        [
          "rule_toggled",
          "category_toggled",
          "repository_added",
          "repository_deleted",
          "ruleset_created",
          "ruleset_updated",
          "ruleset_assigned_to_pool",
          "rules_deployed",
          "ruleset_unassigned_from_pool",
          "ruleset_deleted"
        ],
        &audited?/1
      )
    end
  end

  defp audited?(action) do
    Repo.exists?(
      from(a in AuditEntry,
        where: a.action == ^action,
        where: not is_nil(a.detail) and a.detail != ""
      )
    )
  end

  defp reset_rule_store! do
    Repo.delete_all(AuditEntry)
    Repo.delete_all(PoolRulesetAssignment)
    Repo.delete_all(RulesetRule)
    Repo.delete_all(Ruleset)
    Repo.delete_all(SuricataRule)
    Repo.delete_all(RuleRepository)
    Repo.delete_all(SensorPod)
    Repo.delete_all(SensorPool)
  end

  defp insert_rule!(sid, category) do
    %SuricataRule{}
    |> SuricataRule.changeset(%{
      sid: sid,
      message: "Audit property rule #{sid}",
      raw_text:
        ~s|alert ip any any -> any any (msg:"Audit property rule #{sid}"; classtype:trojan-activity; sid:#{sid}; rev:1;)|,
      category: category,
      classtype: "trojan-activity",
      severity: 2,
      revision: 1,
      enabled: true
    })
    |> Repo.insert!()
  end

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "audit-property")
    |> Repo.insert!()
  end

  defp insert_sensor!(name, pool_id) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "audit-property"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end
end
