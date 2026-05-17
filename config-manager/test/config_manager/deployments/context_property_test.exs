defmodule ConfigManager.Deployments.ContextPropertyTest do
  @moduledoc "Property coverage for deployment context creation, guards, rollback, and filtering."

  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.{Deployments, Pools, Repo, SensorPod, SensorPool}
  alias ConfigManager.Deployments.{Deployment, DeploymentResult}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  property "Property 4 and 6: deployment creation records versions and per-sensor result state",
           [:verbose, numtests: 25] do
    forall code <- integer(1, 1_000) do
      pool =
        create_pool!("creation-prop-#{code}")
        |> set_pool_version!(rem(code, 7) + 1)

      flags = deployable_flags(code)

      sensors =
        flags
        |> Enum.with_index(1)
        |> Enum.map(fn {deployable?, index} ->
          insert_sensor!("creation-prop-#{code}-#{index}", pool.id, deployable?)
        end)

      {:ok, deployment} =
        Deployments.create_deployment(pool, "property-operator", start_orchestrator?: false)

      results = Repo.all(from_result(deployment.id))
      deployable_count = Enum.count(flags, & &1)

      deployment.config_version == pool.config_version and
        deployment.config_snapshot["capture"]["version"] == pool.config_version and
        length(results) == length(sensors) and
        Enum.count(results, &(&1.status == "pending")) == deployable_count and
        Enum.count(results, &(&1.status == "skipped")) == length(sensors) - deployable_count
    end
  end

  property "Property 5: active deployments prevent concurrent deployment creation",
           [:verbose, numtests: 40] do
    forall code <- integer(0, 500) do
      status = Enum.at(Deployment.statuses(), rem(code, length(Deployment.statuses())))
      pool = create_pool!("concurrency-prop-#{code}")
      insert_sensor!("concurrency-prop-#{code}-sensor", pool.id, true)

      {:ok, deployment} =
        Deployments.create_deployment(pool, "property-operator", start_orchestrator?: false)

      _deployment = force_status!(deployment, status)

      result =
        Deployments.create_deployment(pool, "property-operator", start_orchestrator?: false)

      if status in Deployment.active_statuses() do
        result == {:error, :active_deployment_exists}
      else
        match?({:ok, %Deployment{}}, result)
      end
    end
  end

  property "Property 12: rollback guard conditions reject invalid rollback attempts",
           [:verbose, numtests: 30] do
    forall code <- integer(0, 300) do
      guard_case = Enum.at([:already_rolled_back, :active_deployment, :no_previous], rem(code, 3))

      case guard_case do
        :already_rolled_back ->
          pool = create_pool!("rollback-rolled-back-prop-#{code}")
          insert_sensor!("rollback-rolled-back-prop-#{code}-sensor", pool.id, true)

          {:ok, deployment} =
            Deployments.create_deployment(pool, "property-operator", start_orchestrator?: false)

          deployment = force_status!(deployment, "rolled_back")

          Deployments.rollback_deployment(deployment, "property-operator",
            start_orchestrator?: false
          ) == {:error, :already_rolled_back}

        :active_deployment ->
          pool = create_pool!("rollback-active-prop-#{code}")
          insert_sensor!("rollback-active-prop-#{code}-sensor", pool.id, true)
          source = create_terminal_deployment!(pool, "successful", "source")
          target = create_terminal_deployment!(pool, "failed", "target")

          {:ok, _active} =
            Deployments.create_deployment(pool, "property-operator", start_orchestrator?: false)

          _ = source

          Deployments.rollback_deployment(target, "property-operator", start_orchestrator?: false) ==
            {:error, :active_deployment_exists}

        :no_previous ->
          pool = create_pool!("rollback-no-previous-prop-#{code}")
          insert_sensor!("rollback-no-previous-prop-#{code}-sensor", pool.id, true)
          target = create_terminal_deployment!(pool, "failed", "target")

          Deployments.rollback_deployment(target, "property-operator", start_orchestrator?: false) ==
            {:error, :no_previous_successful_deployment}
      end
    end
  end

  property "Property 17: deployment list filtering returns matching deployments in descending time order",
           [:verbose, numtests: 25] do
    forall code <- integer(0, 500) do
      statuses = Deployment.statuses()

      operators =
        ["alice", "bob", "carol"]
        |> Enum.map(&unique_name("list-filter-prop-#{code}-#{&1}"))

      filter_status = Enum.at(statuses, rem(code, length(statuses)))
      filter_operator = Enum.at(operators, rem(div(code, 3), length(operators)))

      deployments =
        0..5
        |> Enum.map(fn index ->
          pool = create_pool!("list-filter-prop-#{code}-#{index}")
          insert_sensor!("list-filter-prop-#{code}-#{index}-sensor", pool.id, true)

          operator = Enum.at(operators, rem(code + index, length(operators)))
          status = Enum.at(statuses, rem(code + index, length(statuses)))

          {:ok, deployment} =
            Deployments.create_deployment(pool, operator, start_orchestrator?: false)

          force_status!(deployment, status)
        end)

      expected_ids =
        deployments
        |> Enum.filter(&(&1.status == filter_status and &1.operator == filter_operator))
        |> MapSet.new(& &1.id)

      page =
        Deployments.list_deployments(
          status: filter_status,
          operator: filter_operator,
          page_size: 10
        )

      returned_ids = MapSet.new(page.entries, & &1.id)

      returned_ids == expected_ids and
        Enum.all?(page.entries, &(&1.status == filter_status and &1.operator == filter_operator)) and
        sorted_desc_by_inserted_at?(page.entries)
    end
  end

  defp create_pool!(name) do
    {:ok, pool} = Pools.create_pool(%{"name" => unique_name(name)}, "property-operator")
    pool
  end

  defp set_pool_version!(%SensorPool{} = pool, version) do
    pool
    |> Ecto.Changeset.change(config_version: version)
    |> Repo.update!()
  end

  defp deployable_flags(code) do
    0..3
    |> Enum.map(&(Bitwise.band(code, Bitwise.bsl(1, &1)) != 0))
    |> ensure_deployable()
  end

  defp ensure_deployable([false | rest]), do: [true | rest]
  defp ensure_deployable(flags), do: flags

  defp insert_sensor!(name, pool_id, deployable?) do
    control_api_host = if deployable?, do: "127.0.0.1", else: nil

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: unique_name(name),
      public_key_pem: "public-key",
      key_fingerprint: unique_name("#{name}-fingerprint"),
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "property-operator",
      control_api_host: control_api_host
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end

  defp create_terminal_deployment!(pool, status, suffix) do
    {:ok, deployment} =
      Deployments.create_deployment(pool, "property-#{suffix}", start_orchestrator?: false)

    force_status!(deployment, status)
  end

  defp force_status!(deployment, status) do
    deployment
    |> Ecto.Changeset.change(status: status, completed_at: terminal_completed_at(status))
    |> Repo.update!()
  end

  defp terminal_completed_at(status)
       when status in ["successful", "failed", "cancelled", "rolled_back"],
       do: DateTime.utc_now()

  defp terminal_completed_at(_status), do: nil

  defp from_result(deployment_id) do
    import Ecto.Query

    from(r in DeploymentResult,
      where: r.deployment_id == ^deployment_id,
      order_by: [asc: r.sensor_pod_id]
    )
  end

  defp sorted_desc_by_inserted_at?([]), do: true
  defp sorted_desc_by_inserted_at?([_entry]), do: true

  defp sorted_desc_by_inserted_at?([left, right | rest]) do
    DateTime.compare(left.inserted_at, right.inserted_at) in [:gt, :eq] and
      sorted_desc_by_inserted_at?([right | rest])
  end

  defp unique_name(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"
end
