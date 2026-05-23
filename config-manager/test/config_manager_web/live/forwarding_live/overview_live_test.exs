defmodule ConfigManagerWeb.ForwardingLive.OverviewLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{AuditEntry, Auth, Forwarding, Pools, Repo}
  alias ConfigManagerWeb.ForwardingLive.OverviewLive

  defp create_user(role) do
    username = "forwarding-live-#{role}-#{System.unique_integer([:positive])}"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Forwarding Live User",
        role: role,
        password: "long-enough-password"
      })

    user
  end

  test "unauthorized forwarding events write permission denied audit metadata" do
    viewer = create_user("viewer")
    {:ok, pool} = Pools.create_pool(%{"name" => "forwarding-live-denied"}, "tester")

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        %{
          "name" => "file-denied",
          "sink_type" => "file",
          "path_template" => "/var/log/ravenwire/events.ndjson",
          "encoding" => "ndjson"
        },
        "tester"
      )

    socket = build_socket(pool, viewer)

    assert {:noreply, denied} =
             OverviewLive.handle_event("toggle_sink", %{"id" => sink.id}, socket)

    assert denied.assigns.flash["error"] == "Insufficient permissions."

    audit =
      Repo.get_by!(AuditEntry,
        action: "permission_denied",
        target_type: "live_event",
        target_id: "forwarding:toggle_sink"
      )

    detail = Jason.decode!(audit.detail)
    assert audit.actor == viewer.username
    assert detail["required_permission"] == "forwarding:manage"
    assert detail["event_or_route"] == "forwarding:toggle_sink"
  end

  test "forwarding PubSub messages reload overview state" do
    viewer = create_user("viewer")
    {:ok, pool} = Pools.create_pool(%{"name" => "forwarding-live-pubsub"}, "tester")
    socket = build_socket(pool, viewer)

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        %{
          "name" => "file-pubsub",
          "sink_type" => "file",
          "path_template" => "/var/log/ravenwire/events.ndjson",
          "encoding" => "ndjson"
        },
        "tester"
      )

    assert {:noreply, created} = OverviewLive.handle_info({:sink_created, sink}, socket)
    assert Enum.map(created.assigns.sinks, & &1.id) == [sink.id]

    {:ok, toggled} = Forwarding.toggle_sink(pool.id, sink.id, "tester")
    assert {:noreply, updated} = OverviewLive.handle_info({:sink_toggled, toggled}, created)
    refute hd(updated.assigns.sinks).enabled

    {:ok, _pool} = Forwarding.update_schema_mode(pool.id, "ecs", "tester")
    assert {:noreply, schema} = OverviewLive.handle_info({:schema_mode_changed, "ecs"}, updated)
    assert schema.assigns.summary.schema_mode == "ecs"

    {:ok, _deleted} = Forwarding.delete_sink(pool.id, sink.id, "tester")
    assert {:noreply, deleted} = OverviewLive.handle_info({:sink_deleted, sink.id}, schema)
    assert deleted.assigns.sinks == []
  end

  defp build_socket(pool, user) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        pool: pool
      },
      private: %{live_temp: %{}}
    }
  end
end
