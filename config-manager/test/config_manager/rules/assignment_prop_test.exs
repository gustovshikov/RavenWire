defmodule ConfigManager.Rules.AssignmentPropTest do
  @moduledoc "Property coverage for pool ruleset assignment and rule sync detection."

  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.Rules
  alias ConfigManager.Rules.{PoolRulesetAssignment, Ruleset, RulesetRule, SuricataRule}
  alias ConfigManager.{AuditEntry, Repo, SensorPod, SensorPool}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  property "Property 8: One ruleset per pool invariant",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      reset_assignment_store!()

      pool = insert_pool!("assignment-prop-pool-#{code}")
      first = insert_ruleset!("assignment-prop-first-#{code}")
      second = insert_ruleset!("assignment-prop-second-#{code}")

      {:ok, _first_assignment} = Rules.assign_ruleset_to_pool(first, pool, "prop")
      {:ok, _second_assignment} = Rules.assign_ruleset_to_pool(second, pool, "prop")

      assignment_count =
        Repo.aggregate(
          from_assignment(pool.id),
          :count,
          :id
        )

      assignment = Rules.pool_assignment(pool.id)

      assignment_count == 1 and assignment.ruleset_id == second.id
    end
  end

  property "Property 10: Out-of-sync detection is correct",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      reset_assignment_store!()

      pool = insert_pool!("sync-prop-pool-#{code}")
      ruleset = insert_ruleset!("sync-prop-ruleset-#{code}")
      version = rem(code, 5) + 1

      ruleset
      |> Ecto.Changeset.change(version: version)
      |> Repo.update!()

      {:ok, _assignment} =
        Rules.assign_ruleset_to_pool(Repo.get!(Ruleset, ruleset.id), pool, "prop")

      deployed_versions = [
        nil,
        version,
        version + 1,
        if(rem(code, 2) == 0, do: version, else: nil)
      ]

      sensors =
        deployed_versions
        |> Enum.with_index(1)
        |> Enum.map(fn {deployed_version, index} ->
          insert_sensor!("sync-prop-sensor-#{code}-#{index}", pool.id, deployed_version)
        end)

      expected_out_of_sync = Enum.count(deployed_versions, &(&1 != version))

      statuses = Rules.sensor_sync_statuses(pool.id)

      Rules.out_of_sync_count(pool.id) == expected_out_of_sync and
        length(statuses) == length(sensors) and
        Enum.count(statuses, & &1.in_sync) ==
          Enum.count(deployed_versions, &(&1 == version)) and
        Enum.all?(statuses, &(&1.expected_version == version))
    end
  end

  defp reset_assignment_store! do
    Repo.delete_all(AuditEntry)
    Repo.delete_all(PoolRulesetAssignment)
    Repo.delete_all(RulesetRule)
    Repo.delete_all(Ruleset)
    Repo.delete_all(SuricataRule)
    Repo.delete_all(SensorPod)
    Repo.delete_all(SensorPool)
  end

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "prop")
    |> Repo.insert!()
  end

  defp insert_ruleset!(name) do
    {:ok, ruleset} = Rules.create_ruleset(%{name: name}, "prop")
    ruleset
  end

  defp insert_sensor!(name, pool_id, deployed_version) do
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
      last_deployed_rule_version: deployed_version
    )
    |> Repo.update!()
  end

  defp from_assignment(pool_id) do
    import Ecto.Query

    from(a in PoolRulesetAssignment, where: a.pool_id == ^pool_id)
  end
end
