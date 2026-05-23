defmodule ConfigManagerWeb.BpfLive.EditorLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Bpf
  alias ConfigManager.{AuditEntry, Auth, Pools, Repo}
  alias ConfigManagerWeb.BpfLive.EditorLive

  defp create_user(role) do
    username = "bpf-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "BPF Live User",
        role: role,
        password: password
      })

    {user, password}
  end

  defp login(conn, role) do
    {user, password} = create_user(role)
    {post(conn, "/login", %{"username" => user.username, "password" => password}), user}
  end

  test "BPF editor route renders empty profile state and hides write controls from viewers", %{
    conn: conn
  } do
    {:ok, pool} = Pools.create_pool(%{"name" => "bpf-viewer-route"}, "tester")

    {logged_conn, _user} = login(conn, "viewer")

    response =
      logged_conn
      |> recycle()
      |> get("/pools/#{pool.id}/bpf")
      |> html_response(200)

    assert response =~ "bpf-viewer-route BPF Filters"
    assert response =~ "No BPF profile exists"
    refute response =~ "Create Profile"
  end

  test "BPF editor route renders profile, rules, preview, and mutation controls for managers", %{
    conn: conn
  } do
    {:ok, pool} = Pools.create_pool(%{"name" => "bpf-manager-route"}, "tester")
    {:ok, profile} = Bpf.create_profile(pool.id, "tester")

    {:ok, _updated} =
      Bpf.save_profile(
        profile,
        %{
          rules: [
            %{
              rule_type: "port_exclusion",
              params: %{"port" => 443, "protocol" => "tcp"},
              label: "tls",
              enabled: true,
              position: 0
            }
          ],
          raw_expression: "udp",
          composition_mode: "append"
        },
        "tester",
        compiler: fn _expression -> {:ok, %{instruction_count: 2}} end
      )

    {logged_conn, _user} = login(conn, "sensor-operator")

    response =
      logged_conn
      |> recycle()
      |> get("/pools/#{pool.id}/bpf")
      |> html_response(200)

    assert response =~ "Port Exclusion"
    assert response =~ "tls"
    assert response =~ "not (port 443 and tcp)"
    assert response =~ "Add Rule"
    assert response =~ "Validate"
    assert response =~ "Save"
  end

  test "rule form events mutate in-memory rules and refresh preview" do
    {user, _password} = create_user("sensor-operator")
    {:ok, pool} = Pools.create_pool(%{"name" => "bpf-rule-events"}, "tester")
    {:ok, profile} = Bpf.create_profile(pool.id, "tester")

    socket = build_socket(pool, profile, user)

    assert {:noreply, with_form} = EditorLive.handle_event("add_rule", %{}, socket)
    assert with_form.assigns.rule_form.rule_type == "port_exclusion"

    assert {:noreply, saved} =
             EditorLive.handle_event(
               "save_rule",
               %{
                 "rule" => %{
                   "rule_type" => "port_exclusion",
                   "label" => "dns",
                   "port" => "53",
                   "protocol" => "udp",
                   "enabled" => "true"
                 }
               },
               with_form
             )

    assert [%{label: "dns", params: %{"port" => "53", "protocol" => "udp"}}] =
             saved.assigns.rules

    assert saved.assigns.compiled_expression == "not (port 53 and udp)"
    assert saved.assigns.dirty

    assert {:noreply, toggled} =
             EditorLive.handle_event("toggle_rule", %{"index" => "0"}, saved)

    refute hd(toggled.assigns.rules).enabled
    assert toggled.assigns.compiled_expression == ""
  end

  test "unauthorized write events are denied and audited" do
    {viewer, _password} = create_user("viewer")
    {:ok, pool} = Pools.create_pool(%{"name" => "bpf-denied"}, "tester")
    socket = build_socket(pool, nil, viewer)

    assert {:noreply, denied} = EditorLive.handle_event("add_rule", %{}, socket)
    assert denied.assigns.flash["error"] == "Insufficient permissions."

    audit =
      Repo.get_by!(AuditEntry,
        action: "permission_denied",
        target_type: "bpf_profile",
        target_id: pool.id
      )

    assert Jason.decode!(audit.detail)["required_permission"] == "bpf:manage"
  end

  test "reset event clears persisted BPF profile state" do
    {user, _password} = create_user("sensor-operator")
    {:ok, pool} = Pools.create_pool(%{"name" => "bpf-reset-event"}, "tester")
    {:ok, profile} = Bpf.create_profile(pool.id, "tester")

    {:ok, updated} =
      Bpf.save_profile(
        profile,
        %{
          rules: [%{rule_type: "port_exclusion", params: %{"port" => 443}, position: 0}],
          raw_expression: "tcp",
          composition_mode: "append"
        },
        "tester",
        compiler: fn _expression -> {:ok, %{instruction_count: 2}} end
      )

    socket =
      pool
      |> build_socket(updated, user)
      |> Map.update!(:assigns, &Map.put(&1, :show_reset_confirm, true))

    assert {:noreply, reset} = EditorLive.handle_event("confirm_reset", %{}, socket)
    assert reset.assigns.profile.version == 3
    assert reset.assigns.rules == []
    assert reset.assigns.compiled_expression == ""
    assert reset.assigns.flash["info"] == "BPF profile reset."
  end

  defp build_socket(pool, profile, user) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        pool: pool,
        profile: profile,
        rules: [],
        raw_expression: "",
        composition_mode: "append",
        compiled_expression: "",
        validation_result: nil,
        validating: false,
        restart_pending_sensors: [],
        restart_pending_count: 0,
        pending_deployment: false,
        dirty: false,
        rule_form: nil,
        show_reset_confirm: false
      },
      private: %{live_temp: %{}}
    }
  end
end
