defmodule ConfigManager.PoolsTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.{Pools, Repo, SensorPod, SensorPool}
  alias ConfigManager.AuditEntry

  test "creates pools with normalized names, defaults, and audit entry" do
    assert {:ok, pool} =
             Pools.create_pool(
               %{"name" => "  Lab_A.1  ", "capture_mode" => "alert_driven"},
               "tester"
             )

    assert pool.name == "Lab_A.1"
    assert pool.config_version == 1
    assert pool.pcap_ring_size_mb == 4096
    assert pool.pre_alert_window_sec == 60
    assert pool.post_alert_window_sec == 30
    assert pool.alert_severity_threshold == 2

    audit = Repo.get_by!(AuditEntry, action: "pool_created", target_id: pool.id)
    assert audit.actor == "tester"
  end

  test "rejects duplicate pool names case-insensitively" do
    assert {:ok, _pool} = Pools.create_pool(%{"name" => "CasePool"}, "tester")
    assert {:error, changeset} = Pools.create_pool(%{"name" => "casepool"}, "tester")
    assert %{name: [_ | _]} = errors_on(changeset)
  end

  test "updates metadata without incrementing config version" do
    {:ok, pool} = Pools.create_pool(%{"name" => "metadata-pool"}, "tester")

    assert {:ok, updated} =
             Pools.update_pool(
               pool,
               %{"name" => "metadata-renamed", "description" => "Lab pool"},
               "tester"
             )

    assert updated.name == "metadata-renamed"
    assert updated.description == "Lab pool"
    assert updated.config_version == pool.config_version
  end

  test "updates config and increments config version only for config changes" do
    {:ok, pool} = Pools.create_pool(%{"name" => "config-pool"}, "tester")

    assert {:ok, unchanged} =
             Pools.update_pool_config(
               pool,
               %{
                 "capture_mode" => pool.capture_mode,
                 "pcap_ring_size_mb" => pool.pcap_ring_size_mb,
                 "pre_alert_window_sec" => pool.pre_alert_window_sec,
                 "post_alert_window_sec" => pool.post_alert_window_sec,
                 "alert_severity_threshold" => pool.alert_severity_threshold
               },
               "tester"
             )

    assert unchanged.config_version == pool.config_version

    assert {:ok, changed} =
             Pools.update_pool_config(pool, %{"pcap_ring_size_mb" => 8192}, "tester")

    assert changed.config_version == pool.config_version + 1
    assert changed.config_updated_by == "tester"
  end

  test "assigns and removes sensors with audit entries" do
    {:ok, pool} = Pools.create_pool(%{"name" => "assignment-pool"}, "tester")
    sensor = insert_sensor!("assignment-sensor")

    assert {:ok, 1} = Pools.assign_sensors(pool, [sensor.id], "tester")
    assert Repo.get!(SensorPod, sensor.id).pool_id == pool.id
    assert Repo.get_by!(AuditEntry, action: "sensor_assigned_to_pool", target_id: sensor.id)

    assert {:ok, 1} = Pools.remove_sensors(pool, [sensor.id], "tester")
    assert Repo.get!(SensorPod, sensor.id).pool_id == nil
    assert Repo.get_by!(AuditEntry, action: "sensor_removed_from_pool", target_id: sensor.id)
  end

  test "deletes pools and nilifies member sensors" do
    {:ok, pool} = Pools.create_pool(%{"name" => "delete-pool"}, "tester")
    sensor = insert_sensor!("delete-sensor", pool.id)

    assert {:ok, %SensorPool{}} = Pools.delete_pool(pool, "tester")
    assert Repo.get!(SensorPod, sensor.id).pool_id == nil
    assert Repo.get_by!(AuditEntry, action: "pool_deleted", target_id: pool.id)
  end

  defp insert_sensor!(name, pool_id \\ nil) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "tester"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
