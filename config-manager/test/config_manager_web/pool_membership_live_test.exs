defmodule ConfigManagerWeb.PoolMembershipLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Auth, Pools, Repo, SensorPod}

  defp create_user(role \\ "platform-admin") do
    username = "pool-membership-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Pool Membership User",
        role: role,
        password: password
      })

    {user, password}
  end

  defp login(conn, role \\ "platform-admin") do
    {user, password} = create_user(role)

    post(conn, "/login", %{"username" => user.username, "password" => password})
  end

  test "pool sensors page renders assignment, move, and bulk removal controls", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "live-pool"}, "tester")
    {:ok, other_pool} = Pools.create_pool(%{"name" => "other-live-pool"}, "tester")
    assigned = insert_sensor!("assigned-live-sensor", pool.id)
    unassigned = insert_sensor!("unassigned-live-sensor")
    movable = insert_sensor!("movable-live-sensor", other_pool.id)

    conn =
      conn
      |> login()
      |> recycle()
      |> get("/pools/#{pool.id}/sensors")

    response = html_response(conn, 200)

    assert response =~ "Assigned Sensors"
    assert response =~ assigned.name
    assert response =~ "Assign Sensors"
    assert response =~ unassigned.name
    assert response =~ "Move from Another Pool"
    assert response =~ movable.name
    assert response =~ other_pool.name
    assert response =~ "Bulk Remove"
    assert response =~ ~s(aria-label="Remove multiple sensors from pool")
  end

  test "moves selected sensors from another pool after confirmation" do
    {:ok, target_pool} = Pools.create_pool(%{"name" => "target-live-pool"}, "tester")
    {:ok, source_pool} = Pools.create_pool(%{"name" => "source-live-pool"}, "tester")
    movable = insert_sensor!("move-confirm-sensor", source_pool.id)
    {user, _password} = create_user()

    socket = build_socket(target_pool, user)

    assert {:noreply, staged} =
             ConfigManagerWeb.PoolLive.SensorsLive.handle_event(
               "stage_move",
               %{"sensor_ids" => [movable.id]},
               socket
             )

    assert staged.assigns.move_sensor_ids == [movable.id]

    assert {:noreply, moved} =
             ConfigManagerWeb.PoolLive.SensorsLive.handle_event("confirm_move", %{}, staged)

    assert Repo.get!(SensorPod, movable.id).pool_id == target_pool.id
    assert moved.assigns.flash["info"] == "Moved 1 sensor(s) into this pool."
  end

  test "bulk removes selected sensors after confirmation" do
    {:ok, pool} = Pools.create_pool(%{"name" => "bulk-live-pool"}, "tester")
    first = insert_sensor!("bulk-live-one", pool.id)
    second = insert_sensor!("bulk-live-two", pool.id)
    {user, _password} = create_user()

    socket = build_socket(pool, user)

    assert {:noreply, staged} =
             ConfigManagerWeb.PoolLive.SensorsLive.handle_event(
               "stage_bulk_remove",
               %{"sensor_ids" => [first.id, second.id]},
               socket
             )

    assert staged.assigns.bulk_remove_sensor_ids == [first.id, second.id]

    assert {:noreply, removed} =
             ConfigManagerWeb.PoolLive.SensorsLive.handle_event(
               "confirm_bulk_remove",
               %{},
               staged
             )

    assert Repo.get!(SensorPod, first.id).pool_id == nil
    assert Repo.get!(SensorPod, second.id).pool_id == nil
    assert removed.assigns.flash["info"] == "Removed 2 sensor(s) from pool."
  end

  test "read-only users do not see mutation controls", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "readonly-live-pool"}, "tester")
    insert_sensor!("readonly-assigned-sensor", pool.id)

    conn =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/pools/#{pool.id}/sensors")

    response = html_response(conn, 200)

    refute response =~ "Assign Sensors"
    refute response =~ "Move from Another Pool"
    refute response =~ "Bulk Remove"
    refute response =~ "Remove from Pool"
  end

  test "read-only users are denied server-side membership mutations" do
    {:ok, pool} = Pools.create_pool(%{"name" => "readonly-event-pool"}, "tester")
    sensor = insert_sensor!("readonly-event-sensor")
    {viewer, _password} = create_user("viewer")
    socket = build_socket(pool, viewer)

    assert {:noreply, denied} =
             ConfigManagerWeb.PoolLive.SensorsLive.handle_event(
               "assign",
               %{"sensor_ids" => [sensor.id]},
               socket
             )

    assert denied.assigns.flash["error"] == "Insufficient permissions."
    assert Repo.get!(SensorPod, sensor.id).pool_id == nil
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

  defp build_socket(pool, user) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        pool: pool,
        current_user: user,
        sensors: Pools.list_pool_sensors(pool.id),
        unassigned_sensors: Pools.list_unassigned_sensors(),
        other_pool_sensors: Pools.list_other_pool_sensors(pool.id),
        remove_sensor_id: nil,
        bulk_remove_sensor_ids: [],
        move_sensor_ids: []
      },
      private: %{live_temp: %{}}
    }
  end
end
