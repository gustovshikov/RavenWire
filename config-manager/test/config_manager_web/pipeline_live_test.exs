defmodule ConfigManagerWeb.PipelineLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias ConfigManager.{Auth, Forwarding, Pools, Repo, SensorPod}
  alias ConfigManager.Health.Registry
  alias ConfigManagerWeb.PipelineGraphComponent

  alias ConfigManagerWeb.PipelineLive.{
    PoolPipelineLive,
    SensorPipelineGraphLive,
    SensorPipelineLive
  }

  test "sensor pipeline route renders pending, enrolled, and revoked sensors", %{conn: conn} do
    viewer_conn = login(conn, "viewer")

    pending = insert_sensor!("pipeline-pending", %{status: "pending"})
    enrolled = insert_sensor!("pipeline-enrolled", %{status: "enrolled"})
    revoked = insert_sensor!("pipeline-revoked", %{status: "revoked"})

    Registry.update(enrolled.name, health_report(enrolled.name))
    Process.sleep(50)

    pending_html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pending.id}/pipeline")
      |> html_response(200)

    assert pending_html =~ "#{pending.name} Pipeline"
    assert pending_html =~ "No Health Data"
    assert pending_html =~ "Pending Enrollment"
    assert pending_html =~ "Mirror Port"
    assert pending_html =~ "Forwarding Sinks"

    enrolled_html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{enrolled.id}/pipeline")
      |> html_response(200)

    assert enrolled_html =~ "#{enrolled.name} Pipeline"
    assert enrolled_html =~ "Live Data Flow"
    assert enrolled_html =~ "AF_PACKET"
    assert enrolled_html =~ "Zeek"
    assert enrolled_html =~ "Suricata"
    assert enrolled_html =~ "PCAP Ring"
    assert enrolled_html =~ "Vector"
    assert enrolled_html =~ "Pipeline Summary"
    assert enrolled_html =~ ~s(/sensors/#{enrolled.id}/pipeline/graph)
    assert enrolled_html =~ "Node Graph"

    revoked_html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{revoked.id}/pipeline")
      |> html_response(200)

    assert revoked_html =~ "#{revoked.name} Pipeline"
    assert revoked_html =~ "Revoked Sensor"
  end

  test "sensor pipeline graph route renders pending, enrolled, and revoked sensors", %{conn: conn} do
    viewer_conn = login(conn, "viewer")

    pending = insert_sensor!("pipeline-graph-pending", %{status: "pending"})
    enrolled = insert_sensor!("pipeline-graph-enrolled", %{status: "enrolled"})
    revoked = insert_sensor!("pipeline-graph-revoked", %{status: "revoked"})

    Registry.update(enrolled.name, health_report(enrolled.name))
    Process.sleep(50)

    pending_html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pending.id}/pipeline/graph")
      |> html_response(200)

    assert pending_html =~ "#{pending.name} Pipeline Node Graph"
    assert pending_html =~ "Live Sensor Node Graph"
    assert pending_html =~ "No Health Data"
    assert pending_html =~ "Pending Enrollment"
    assert pending_html =~ "Linear Pipeline"

    enrolled_html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{enrolled.id}/pipeline/graph")
      |> html_response(200)

    assert enrolled_html =~ "#{enrolled.name} Pipeline Node Graph"
    assert enrolled_html =~ "Mirror Port"
    assert enrolled_html =~ "AF_PACKET"
    assert enrolled_html =~ "Zeek"
    assert enrolled_html =~ "Suricata"
    assert enrolled_html =~ "PCAP Ring"
    assert enrolled_html =~ "Vector"
    assert enrolled_html =~ "Forwarding Sinks"
    assert enrolled_html =~ "pipeline-node-flow-state-flowing pipeline-node-flow-speed-mbps"

    revoked_html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{revoked.id}/pipeline/graph")
      |> html_response(200)

    assert revoked_html =~ "#{revoked.name} Pipeline Node Graph"
    assert revoked_html =~ "Revoked Sensor"
  end

  test "pipeline routes handle missing records and authentication", %{conn: conn} do
    missing_id = Ecto.UUID.generate()

    assert redirected_to(get(conn, "/sensors/#{missing_id}/pipeline")) == "/login"
    assert redirected_to(get(conn, "/sensors/#{missing_id}/pipeline/graph")) == "/login"
    assert redirected_to(get(conn, "/pools/#{missing_id}/pipeline")) == "/login"

    viewer_conn = login(conn, "viewer")

    assert viewer_conn
           |> recycle()
           |> get("/sensors/#{missing_id}/pipeline")
           |> html_response(200) =~ "Sensor Not Found"

    assert viewer_conn
           |> recycle()
           |> get("/sensors/#{missing_id}/pipeline/graph")
           |> html_response(200) =~ "Sensor Not Found"

    assert viewer_conn
           |> recycle()
           |> get("/pools/#{missing_id}/pipeline")
           |> html_response(200) =~ "Pool Not Found"
  end

  test "pool pipeline route renders empty and populated aggregate states", %{conn: conn} do
    viewer_conn = login(conn, "viewer")
    {:ok, empty_pool} = Pools.create_pool(%{"name" => "pipeline-empty-pool"}, "tester")

    empty_html =
      viewer_conn
      |> recycle()
      |> get("/pools/#{empty_pool.id}/pipeline")
      |> html_response(200)

    assert empty_html =~ "pipeline-empty-pool Pipeline"
    assert empty_html =~ "No Sensors Assigned"
    assert empty_html =~ "0"
    assert empty_html =~ "reporting"

    {:ok, pool} = Pools.create_pool(%{"name" => "pipeline-populated-pool"}, "tester")
    first = insert_sensor!("pipeline-pool-first", %{pool_id: pool.id})
    second = insert_sensor!("pipeline-pool-second", %{pool_id: pool.id})
    Registry.update(first.name, health_report(first.name))
    Process.sleep(50)

    html =
      viewer_conn
      |> recycle()
      |> get("/pools/#{pool.id}/pipeline")
      |> html_response(200)

    assert html =~ "pipeline-populated-pool Pipeline"
    assert html =~ first.name
    assert html =~ second.name
    assert html =~ "1"
    assert html =~ "No Data"
    assert html =~ ~s(/sensors/#{first.id}/pipeline)
  end

  test "sensor detail and pool nav link to pipeline routes", %{conn: conn} do
    viewer_conn = login(conn, "viewer")
    {:ok, pool} = Pools.create_pool(%{"name" => "pipeline-nav-pool"}, "tester")
    pod = insert_sensor!("pipeline-nav-sensor", %{pool_id: pool.id})

    sensor_detail =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pod.id}")
      |> html_response(200)

    assert sensor_detail =~ ~s(/sensors/#{pod.id}/pipeline)
    assert sensor_detail =~ "Pipeline"

    pool_detail =
      viewer_conn
      |> recycle()
      |> get("/pools/#{pool.id}")
      |> html_response(200)

    assert pool_detail =~ ~s(/pools/#{pool.id}/pipeline)
    assert pool_detail =~ "Pipeline"
  end

  test "sensor pipeline updates from pod PubSub events" do
    pod = insert_sensor!("pipeline-live-sensor")

    Registry.update(pod.name, health_report(pod.name))
    Process.sleep(50)

    Registry.update(pod.name, health_report(pod.name, drop_percent: 12.0))
    Process.sleep(50)

    assert {:noreply, updated} =
             SensorPipelineLive.handle_info({:pod_updated, pod.name}, build_sensor_socket(pod))

    af_packet = segment(updated.assigns.pipeline_state, "af_packet")
    zeek = segment(updated.assigns.pipeline_state, "zeek")

    assert af_packet.state == :degraded
    assert zeek.state == :degraded
  end

  test "pool pipeline debounces member health updates and re-renders aggregate counts" do
    {:ok, pool} = Pools.create_pool(%{"name" => "pipeline-live-pool"}, "tester")
    first = insert_sensor!("pipeline-live-first", %{pool_id: pool.id})
    second = insert_sensor!("pipeline-live-second", %{pool_id: pool.id})

    Registry.update(first.name, health_report(first.name))
    Registry.update(second.name, health_report(second.name))
    Process.sleep(50)

    Registry.update(first.name, health_report(first.name, drop_percent: 16.0))
    Process.sleep(50)

    assert {:noreply, scheduled} =
             PoolPipelineLive.handle_info(
               {:pod_updated, first.name},
               build_pool_socket(pool, [first, second])
             )

    assert is_reference(scheduled.assigns.debounce_token)

    assert {:noreply, updated} =
             PoolPipelineLive.handle_info(
               {:rederive, scheduled.assigns.debounce_token},
               scheduled
             )

    af_packet = segment(updated.assigns.aggregate_state, "af_packet")

    assert af_packet.overall_state == :degraded
    assert af_packet.state_counts.healthy == 1
    assert af_packet.state_counts.degraded == 1
    assert updated.assigns.aggregate_state.reporting_members == 2
  end

  test "forwarding config changes are reflected as labels without runtime health inference", %{
    conn: conn
  } do
    viewer_conn = login(conn, "viewer")
    {:ok, pool} = Pools.create_pool(%{"name" => "pipeline-forwarding-pool"}, "tester")

    {:ok, _sink} =
      Forwarding.create_sink(
        pool.id,
        %{
          "name" => "pipeline-file-sink",
          "sink_type" => "file",
          "path_template" => "/var/log/ravenwire/events.ndjson",
          "encoding" => "ndjson"
        },
        "tester"
      )

    pod = insert_sensor!("pipeline-forwarding-sensor", %{pool_id: pool.id})
    Registry.update(pod.name, health_report(pod.name))
    Process.sleep(50)

    html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pod.id}/pipeline")
      |> html_response(200)

    assert html =~ "pipeline-file-sink"
    assert html =~ "1/1 enabled"
    assert html =~ "runtime no data"
    assert html =~ "Forwarding sink runtime telemetry is not available"
  end

  test "sensor pipeline graph node clicks toggle and swap the detail drawer" do
    pod = insert_sensor!("pipeline-graph-select-sensor")
    Registry.update(pod.name, health_report(pod.name))
    Process.sleep(50)

    assert {:noreply, loaded} =
             SensorPipelineGraphLive.handle_info(
               {:pod_updated, pod.name},
               build_sensor_graph_socket(pod)
             )

    assert loaded.assigns.selected_segment_id == "af_packet"
    assert loaded.assigns.detail_panel_open == false

    assert {:noreply, focused_socket} =
             SensorPipelineGraphLive.handle_event(
               "focus_segment",
               %{"id" => "suricata"},
               loaded
             )

    assert focused_socket.assigns.selected_segment_id == "suricata"
    assert focused_socket.assigns.detail_panel_open == false

    assert {:noreply, opened_socket} =
             SensorPipelineGraphLive.handle_event(
               "select_segment",
               %{"id" => "suricata"},
               focused_socket
             )

    assert opened_socket.assigns.selected_segment_id == "suricata"
    assert opened_socket.assigns.detail_panel_open == true

    assert {:noreply, still_suricata_socket} =
             SensorPipelineGraphLive.handle_event(
               "focus_segment",
               %{"id" => "af_packet"},
               opened_socket
             )

    assert still_suricata_socket.assigns.selected_segment_id == "suricata"
    assert still_suricata_socket.assigns.detail_panel_open == true

    assert {:noreply, swapped_socket} =
             SensorPipelineGraphLive.handle_event(
               "select_segment",
               %{"id" => "af_packet"},
               still_suricata_socket
             )

    assert swapped_socket.assigns.selected_segment_id == "af_packet"
    assert swapped_socket.assigns.detail_panel_open == true

    assert {:noreply, closed_socket} =
             SensorPipelineGraphLive.handle_event(
               "select_segment",
               %{"id" => "af_packet"},
               swapped_socket
             )

    assert closed_socket.assigns.selected_segment_id == "af_packet"
    assert closed_socket.assigns.detail_panel_open == false

    html =
      render_component(&PipelineGraphComponent.sensor_pipeline_graph/1,
        pipeline_state: swapped_socket.assigns.pipeline_state,
        selected_segment_id: swapped_socket.assigns.selected_segment_id,
        detail_panel_open: swapped_socket.assigns.detail_panel_open
      )

    document = Floki.parse_fragment!(html)
    selected = Floki.find(document, "#pipeline-node-segment-af_packet") |> List.first()
    toggle = Floki.find(document, ".pipeline-node-detail-toggle") |> List.first()
    panel = Floki.find(document, "#pipeline-node-detail-panel") |> List.first()

    assert attribute(selected, "aria-pressed") == "true"
    assert attribute(selected, "class") =~ "pipeline-node-selected"
    assert attribute(toggle, "aria-expanded") == "true"
    assert attribute(panel, "aria-hidden") == "false"
    assert Floki.find(document, ".pipeline-node-detail h3") |> Floki.text() == "AF_PACKET"
  end

  test "sensor pipeline graph re-renders state and flow classes from PubSub updates" do
    pod = insert_sensor!("pipeline-graph-live-sensor")

    Registry.update(pod.name, health_report(pod.name, drop_percent: 12.0))
    Process.sleep(50)

    assert {:noreply, updated} =
             SensorPipelineGraphLive.handle_info(
               {:pod_updated, pod.name},
               build_sensor_graph_socket(pod)
             )

    html =
      render_component(&PipelineGraphComponent.sensor_pipeline_graph/1,
        pipeline_state: updated.assigns.pipeline_state,
        selected_segment_id: updated.assigns.selected_segment_id,
        detail_panel_open: updated.assigns.detail_panel_open
      )

    assert html =~ "pipeline-node-state-degraded"
    assert html =~ "pipeline-node-flow-state-degraded pipeline-node-flow-speed-mbps"
  end

  defp login(conn, role) do
    username = "pipeline-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, _user} =
      Auth.create_user(%{
        username: username,
        display_name: "Pipeline Live User",
        role: role,
        password: password
      })

    post(conn, "/login", %{"username" => username, "password" => password})
  end

  defp insert_sensor!(name, attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    unique_name = "#{name}-#{System.unique_integer([:positive])}"

    pod =
      %SensorPod{}
      |> SensorPod.enrollment_changeset(%{
        name: unique_name,
        public_key_pem: "public-key",
        key_fingerprint: "#{unique_name}-fingerprint",
        enrolled_at: now,
        enrolled_by: "tester"
      })
      |> Repo.insert!()

    update_attrs =
      %{
        status: "enrolled",
        cert_serial: "#{unique_name}-serial",
        cert_expires_at: DateTime.add(now, 7 * 24 * 60 * 60, :second)
      }
      |> Map.merge(attrs)

    pod
    |> Ecto.Changeset.change(update_attrs)
    |> Repo.update!()
  end

  defp health_report(pod_name, opts \\ []) do
    drop_percent = Keyword.get(opts, :drop_percent, 0.0)

    %Health.HealthReport{
      sensor_pod_id: pod_name,
      timestamp_unix_ms: DateTime.utc_now() |> DateTime.to_unix(:millisecond),
      system: %Health.SystemStats{
        capture_interface: "ens16f1",
        nic_driver: "ixgbe",
        af_packet_available: true
      },
      containers: [
        %Health.ContainerHealth{name: "systemd-zeek", state: "running", cpu_percent: 20.0},
        %Health.ContainerHealth{name: "systemd-suricata", state: "running", cpu_percent: 20.0},
        %Health.ContainerHealth{
          name: "systemd-pcap-ring-writer",
          state: "running",
          cpu_percent: 20.0
        },
        %Health.ContainerHealth{name: "systemd-vector", state: "running", cpu_percent: 20.0}
      ],
      capture: %Health.CaptureStats{
        consumers: %{
          "zeek" => %Health.ConsumerStats{
            packets_received: 1_000,
            drop_percent: drop_percent,
            throughput_bps: 2_000_000
          },
          "suricata" => %Health.ConsumerStats{
            packets_received: 1_000,
            drop_percent: 0.0,
            throughput_bps: 2_000_000
          },
          "pcap_ring_writer" => %Health.ConsumerStats{
            packets_received: 1_000,
            drop_percent: 0.0,
            throughput_bps: 2_000_000
          }
        }
      },
      storage: %Health.StorageStats{
        path: "/var/lib/ravenwire/pcap",
        total_bytes: 1_000_000,
        used_bytes: 500_000,
        used_percent: 50.0
      }
    }
  end

  defp build_sensor_socket(pod) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        pod: pod,
        health_key: pod.name
      },
      private: %{live_temp: %{}}
    }
  end

  defp build_sensor_graph_socket(pod, selected_segment_id \\ "af_packet") do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        pod: pod,
        health_key: pod.name,
        selected_segment_id: selected_segment_id,
        detail_panel_open: false
      },
      private: %{live_temp: %{}}
    }
  end

  defp build_pool_socket(pool, members) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        pool: pool,
        members: members,
        member_health_keys: members |> Enum.map(& &1.name) |> MapSet.new(),
        debounce_timer: nil,
        debounce_token: nil
      },
      private: %{live_temp: %{}}
    }
  end

  defp segment(pipeline_state, id) do
    Enum.find(pipeline_state.segments, &(&1.id == id))
  end

  defp attribute(node, name) do
    node
    |> Floki.attribute(name)
    |> List.first()
  end
end
