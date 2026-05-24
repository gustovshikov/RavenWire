defmodule ConfigManagerWeb.AlertLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Alerts
  alias ConfigManager.Alerts.{Alert, AlertRule}
  alias ConfigManager.{AuditEntry, Auth, Repo, SensorPod}
  alias ConfigManagerWeb.{AlertDashboardLive, AlertRulesLive}

  setup do
    Repo.delete_all(Alert)
    Repo.delete_all(AlertRule)
    Alerts.seed_default_rules()
    :ok
  end

  test "alert routes render with expected RBAC", %{conn: conn} do
    {viewer_conn, _viewer} = login(conn, "viewer")

    alerts =
      viewer_conn
      |> recycle()
      |> get("/alerts")
      |> html_response(200)

    assert alerts =~ "Alerts"
    assert alerts =~ "Apply Filters"

    notifications =
      viewer_conn
      |> recycle()
      |> get("/alerts/notifications")
      |> html_response(200)

    assert notifications =~ "Alert Notifications"
    assert notifications =~ "planned for a future release"

    denied =
      viewer_conn
      |> recycle()
      |> get("/alerts/rules")

    assert response(denied, 403) =~ "Forbidden"

    {operator_conn, _operator} = login(conn, "sensor-operator")

    rules =
      operator_conn
      |> recycle()
      |> get("/alerts/rules")
      |> html_response(200)

    assert rules =~ "Alert Rules"
    assert rules =~ "Deferred source"
  end

  test "dashboard events enforce RBAC and transition alerts" do
    viewer = create_user("viewer")
    admin = create_user("platform-admin")
    pod = insert_sensor!("alert-live-sensor")
    alert = fire!(pod)

    denied_socket = dashboard_socket(viewer)

    assert {:noreply, denied} =
             AlertDashboardLive.handle_event("ack", %{"id" => alert.id}, denied_socket)

    assert denied.assigns.flash["error"] == "Insufficient permissions."

    audit = Repo.get_by!(AuditEntry, action: "permission_denied", target_id: "alert:acknowledge")
    assert Jason.decode!(audit.detail)["required_permission"] == "alerts:manage"

    admin_socket = dashboard_socket(admin)

    assert {:noreply, acked_socket} =
             AlertDashboardLive.handle_event("ack", %{"id" => alert.id}, admin_socket)

    assert acked_socket.assigns.flash["info"] == "Alert acknowledged."
    assert Repo.get!(Alert, alert.id).status == "acknowledged"

    assert {:noreply, resolved_socket} =
             AlertDashboardLive.handle_event("resolve", %{"id" => alert.id}, acked_socket)

    assert resolved_socket.assigns.flash["info"] == "Alert resolved."
    assert Repo.get!(Alert, alert.id).status == "resolved"
  end

  test "alert rule LiveView save validates and audits changes" do
    admin = create_user("platform-admin")
    rule = Repo.get_by!(AlertRule, alert_type: "disk_critical")
    socket = rules_socket(admin)

    assert {:noreply, updated_socket} =
             AlertRulesLive.handle_event(
               "save",
               %{
                 "rule_id" => rule.id,
                 "rule" => %{
                   "severity" => "warning",
                   "enabled" => "true",
                   "threshold_value" => "91"
                 }
               },
               socket
             )

    assert updated_socket.assigns.flash["info"] == "Alert rule updated."
    assert Repo.get!(AlertRule, rule.id).threshold_value == 91.0
    assert Repo.get_by!(AuditEntry, action: "alert_rule_updated", target_id: rule.id)

    assert {:noreply, invalid_socket} =
             AlertRulesLive.handle_event(
               "save",
               %{
                 "rule_id" => rule.id,
                 "rule" => %{
                   "severity" => "warning",
                   "enabled" => "true",
                   "threshold_value" => "101"
                 }
               },
               socket
             )

    refute invalid_socket.assigns.changeset.valid?
  end

  test "sensor detail page shows active alert summary and filtered link", %{conn: conn} do
    {viewer_conn, _viewer} = login(conn, "viewer")
    pod = insert_sensor!("alert-detail-sensor")
    alert = fire!(pod)

    html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pod.id}")
      |> html_response(200)

    assert html =~ "Active Alerts"
    assert html =~ alert.message
    assert html =~ "/alerts?sensor_pod_id=#{pod.name}"
  end

  defp dashboard_socket(user) do
    {alerts, meta} = Alerts.list_alerts(%{}, %{})

    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        alerts: alerts,
        filters: %{},
        page: 1,
        meta: meta,
        counts: Alerts.alert_status_counts()
      },
      private: %{live_temp: %{}}
    }
  end

  defp rules_socket(user) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        rules: Alerts.list_rules(),
        changeset: nil
      },
      private: %{live_temp: %{}}
    }
  end

  defp fire!(pod) do
    {:ok, alert} =
      Alerts.fire_alert(%{
        alert_type: "disk_critical",
        sensor_pod_id: pod.name,
        sensor_pod_db_id: pod.id,
        severity: "critical",
        message: "Sensor #{pod.name} storage is critical.",
        threshold_value: 90.0,
        observed_value: 95.0
      })

    alert
  end

  defp login(conn, role) do
    user = create_user(role)

    {post(conn, "/login", %{"username" => user.username, "password" => "long-enough-password"}),
     user}
  end

  defp create_user(role) do
    username = "alert-live-#{role}-#{System.unique_integer([:positive])}"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Alert Live User",
        role: role,
        password: "long-enough-password"
      })

    user
  end

  defp insert_sensor!(name) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: now,
      enrolled_by: "tester"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(%{
      status: "enrolled",
      cert_serial: "#{name}-serial",
      cert_expires_at: DateTime.add(now, 7 * 24 * 60 * 60, :second)
    })
    |> Repo.update!()
  end
end
