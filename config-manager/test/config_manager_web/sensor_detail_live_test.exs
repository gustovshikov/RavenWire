defmodule ConfigManagerWeb.SensorDetailLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Auth, Forwarding, Pools, Repo, SensorPod}
  alias ConfigManager.AuditEntry
  alias ConfigManager.Health.Registry

  defp create_user(role) do
    username = "sensor-detail-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Sensor Detail User",
        role: role,
        password: password
      })

    {user, password}
  end

  defp login(conn, role \\ "platform-admin") do
    {user, password} = create_user(role)
    post(conn, "/login", %{"username" => user.username, "password" => password})
  end

  defmodule SuccessClient do
    def validate_config(_pod), do: {:ok, %{"status" => "valid", "token" => "redacted"}}
    def reload_zeek(_pod), do: {:ok, %{"status" => "reloaded"}}
    def reload_suricata(_pod), do: {:ok, %{"status" => "reloaded"}}
    def restart_vector(_pod), do: {:ok, %{"status" => "restarted"}}
    def request_support_bundle(_pod), do: {:ok, %{"bundle_path" => "/tmp/support.tar.gz"}}
  end

  defmodule SlowClient do
    def validate_config(_pod) do
      Process.sleep(200)
      {:ok, %{"status" => "valid"}}
    end

    def reload_zeek(_pod), do: {:ok, %{}}
    def reload_suricata(_pod), do: {:ok, %{}}
    def restart_vector(_pod), do: {:ok, %{}}
    def request_support_bundle(_pod), do: {:ok, %{}}
  end

  defp insert_pod(attrs \\ %{}) do
    defaults = %{
      name: "sensor-detail-pod-#{System.unique_integer([:positive])}",
      public_key_pem: "public-key",
      key_fingerprint: "fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "test",
      status: "pending"
    }

    pod =
      %SensorPod{}
      |> SensorPod.enrollment_changeset(Map.merge(defaults, attrs))
      |> Repo.insert!()

    updatable =
      Map.take(attrs, [
        :status,
        :cert_serial,
        :cert_expires_at,
        :control_api_host,
        :last_seen_at,
        :pool_id
      ])

    if updatable == %{} do
      pod
    else
      pod
      |> Ecto.Changeset.change(updatable)
      |> Repo.update!()
    end
  end

  test "renders existing pending sensor identity and empty health sections", %{conn: conn} do
    pod = insert_pod()

    conn =
      conn
      |> login()
      |> recycle()
      |> get("/sensors/#{pod.id}")

    response = html_response(conn, 200)

    assert response =~ pod.name
    assert response =~ "Pending enrollment"
    assert response =~ "This sensor is not currently reporting health data"
    assert response =~ "No container data is available"
    assert response =~ "No pool assigned"
    assert response =~ "Forwarding telemetry is not yet available"
    refute response =~ "public-key"
  end

  test "renders 404 message for missing sensor", %{conn: conn} do
    missing_id = Ecto.UUID.generate()

    conn =
      conn
      |> login()
      |> recycle()
      |> get("/sensors/#{missing_id}")

    assert html_response(conn, 200) =~ "Sensor Not Found"
  end

  test "renders health report sections for enrolled sensor", %{conn: conn} do
    pod =
      insert_pod(%{
        status: "enrolled",
        cert_serial: "ABC123",
        cert_expires_at:
          DateTime.utc_now() |> DateTime.add(31, :day) |> DateTime.truncate(:second),
        control_api_host: "127.0.0.1"
      })

    Registry.update(pod.name, health_report(pod.name))
    Process.sleep(50)

    conn =
      conn
      |> login()
      |> recycle()
      |> get("/sensors/#{pod.id}")

    response = html_response(conn, 200)

    assert response =~ "ABC123"
    assert response =~ "Containers"
    assert response =~ "systemd-zeek"
    assert response =~ "systemd-suricata"
    assert response =~ "systemd-vector"
    assert response =~ "systemd-pcap-ring-writer"
    assert response =~ "systemd-config-manager"
    assert response =~ "systemd-sensor-agent"
    assert response =~ "Capture / Sensor Plane"
    assert response =~ "Management Plane"
    refute response =~ ">zeek</th>"
    refute response =~ ">suricata</th>"
    refute response =~ ">vector</th>"
    refute response =~ ">pcap_ring_writer</th>"
    refute response =~ "missing"
    assert response =~ "Capture Pipeline"
    assert response =~ "pcap"
    assert response =~ "Storage"
    assert response =~ "/var/lib/ravenwire/pcap"
    assert response =~ "Clock"
    assert response =~ "chrony"
    assert response =~ "6.8.0-ravenwire"
    assert response =~ "ens16f1"
    assert response =~ "ixgbe"
    assert response =~ "available"
  end

  test "dashboard links health rows to sensor detail page when database identity exists", %{
    conn: conn
  } do
    pod = insert_pod(%{status: "enrolled"})
    Registry.update(pod.name, health_report(pod.name))
    Process.sleep(50)

    conn =
      conn
      |> login()
      |> recycle()
      |> get("/")

    response = html_response(conn, 200)

    assert response =~ ~s(href="/sensors/#{pod.id}")
    assert response =~ ~s(aria-label="View details for #{pod.name}")
    assert response =~ "Disk Free"
    assert response =~ "Capture Plane"
    assert response =~ "Management Plane"
    assert response =~ "Max Drop"
    refute response =~ "Capture Consumers"
  end

  test "dashboard marks stale health rows instead of reporting them as current", %{conn: conn} do
    pod = insert_pod(%{status: "enrolled"})
    stale_at = DateTime.utc_now() |> DateTime.add(-120, :second)

    Registry.update(pod.name, health_report(pod.name, timestamp: stale_at))
    Process.sleep(50)

    conn =
      conn
      |> login()
      |> recycle()
      |> get("/")

    response = html_response(conn, 200)

    assert response =~ ~s(aria-label="View details for #{pod.name}")
    assert response =~ ~r/View details for #{Regex.escape(pod.name)}.*Health data is stale\./s
    assert response =~ ~r/View details for #{Regex.escape(pod.name)}.*>\s*stale\s*</s
  end

  test "renders forwarding pool configuration for assigned sensors", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "sensor-forwarding-pool"}, "tester")

    {:ok, _sink} =
      Forwarding.create_sink(
        pool.id,
        %{
          "name" => "sensor-file-sink",
          "sink_type" => "file",
          "path_template" => "/var/log/ravenwire/events.ndjson",
          "encoding" => "ndjson"
        },
        "tester"
      )

    pod = insert_pod(%{status: "enrolled", pool_id: pool.id})

    conn =
      conn
      |> login()
      |> recycle()
      |> get("/sensors/#{pod.id}")

    response = html_response(conn, 200)
    assert response =~ "sensor-forwarding-pool"
    assert response =~ "Schema mode: Raw"
    assert response =~ "1/1 sinks enabled"
    assert response =~ "sensor-file-sink"
    assert response =~ "File"
    assert response =~ "Forwarding telemetry is not yet available"
  end

  test "sensor actions run asynchronously and write sanitized audit success" do
    put_sensor_action_env(SuccessClient, 1_000)

    pod =
      insert_pod(%{
        status: "enrolled",
        control_api_host: "127.0.0.1"
      })

    {user, _password} = create_user("sensor-operator")
    socket = build_action_socket(pod, user, 1_000)

    assert {:noreply, running} =
             ConfigManagerWeb.SensorDetailLive.handle_event(
               "action",
               %{"action" => "validate_config"},
               socket
             )

    assert MapSet.member?(running.assigns.in_flight_actions, "validate_config")
    %{ref: ref} = running.assigns.action_tasks["validate_config"]
    assert_receive {^ref, {:ok, %{"status" => "valid", "token" => "redacted"}}}, 500

    assert {:noreply, finished} =
             ConfigManagerWeb.SensorDetailLive.handle_info(
               {ref, {:ok, %{"status" => "valid", "token" => "redacted"}}},
               running
             )

    assert finished.assigns.flash["info"] == "Validate Config completed."
    refute MapSet.member?(finished.assigns.in_flight_actions, "validate_config")

    audit =
      Repo.get_by!(AuditEntry,
        action: "sensor_validate_config",
        target_id: pod.id,
        result: "success"
      )

    assert audit.detail =~ "valid"
    refute audit.detail =~ "redacted"
  end

  test "sensor actions time out without blocking the LiveView" do
    put_sensor_action_env(SlowClient, 20)

    pod =
      insert_pod(%{
        status: "enrolled",
        control_api_host: "127.0.0.1"
      })

    {user, _password} = create_user("sensor-operator")
    socket = build_action_socket(pod, user, 20)

    assert {:noreply, running} =
             ConfigManagerWeb.SensorDetailLive.handle_event(
               "action",
               %{"action" => "validate_config"},
               socket
             )

    %{ref: ref} = running.assigns.action_tasks["validate_config"]

    assert {:noreply, timed_out} =
             ConfigManagerWeb.SensorDetailLive.handle_info(
               {:sensor_action_timeout, "validate_config", ref},
               running
             )

    assert timed_out.assigns.flash["error"] == "Validate Config failed: Action timed out"
    refute MapSet.member?(timed_out.assigns.in_flight_actions, "validate_config")

    assert Repo.get_by!(AuditEntry,
             action: "sensor_validate_config",
             target_id: pod.id,
             result: "failure"
           )
  end

  defp put_sensor_action_env(client, timeout_ms) do
    previous_client = Application.get_env(:config_manager, :sensor_agent_client)
    previous_timeout = Application.get_env(:config_manager, :sensor_detail_action_timeout_ms)

    Application.put_env(:config_manager, :sensor_agent_client, client)
    Application.put_env(:config_manager, :sensor_detail_action_timeout_ms, timeout_ms)

    on_exit(fn ->
      restore_env(:sensor_agent_client, previous_client)
      restore_env(:sensor_detail_action_timeout_ms, previous_timeout)
    end)
  end

  defp restore_env(key, nil), do: Application.delete_env(:config_manager, key)
  defp restore_env(key, value), do: Application.put_env(:config_manager, key, value)

  defp build_action_socket(pod, user, timeout_ms) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        pod: pod,
        in_flight_actions: MapSet.new(),
        action_tasks: %{},
        action_timeout_ms: timeout_ms
      },
      private: %{live_temp: %{}}
    }
  end

  defp health_report(pod_name, opts \\ []) do
    timestamp =
      opts
      |> Keyword.get(:timestamp, DateTime.utc_now())
      |> DateTime.to_unix(:millisecond)

    %Health.HealthReport{
      sensor_pod_id: pod_name,
      timestamp_unix_ms: timestamp,
      containers: [
        %Health.ContainerHealth{
          name: "systemd-zeek",
          state: "running",
          uptime_seconds: 3_600,
          cpu_percent: 12.5,
          memory_bytes: 128_000_000
        },
        %Health.ContainerHealth{
          name: "systemd-suricata",
          state: "running",
          uptime_seconds: 3_500,
          cpu_percent: 8.0,
          memory_bytes: 96_000_000
        },
        %Health.ContainerHealth{
          name: "systemd-vector",
          state: "running",
          uptime_seconds: 3_400,
          cpu_percent: 15.0,
          memory_bytes: 64_000_000
        },
        %Health.ContainerHealth{
          name: "systemd-pcap-ring-writer",
          state: "running",
          uptime_seconds: 3_300,
          cpu_percent: 4.0,
          memory_bytes: 32_000_000
        },
        %Health.ContainerHealth{
          name: "systemd-config-manager",
          state: "running",
          uptime_seconds: 3_200,
          cpu_percent: 2.0,
          memory_bytes: 160_000_000
        },
        %Health.ContainerHealth{
          name: "systemd-sensor-agent",
          state: "running",
          uptime_seconds: 3_100,
          cpu_percent: 1.0,
          memory_bytes: 24_000_000
        }
      ],
      capture: %Health.CaptureStats{
        consumers: %{
          "pcap" => %Health.ConsumerStats{
            packets_received: 1000,
            packets_dropped: 1,
            drop_percent: 0.1,
            throughput_bps: 1_000_000,
            bpf_restart_pending: false
          }
        }
      },
      storage: %Health.StorageStats{
        path: "/var/lib/ravenwire/pcap",
        total_bytes: 100_000_000,
        used_bytes: 50_000_000,
        available_bytes: 50_000_000,
        used_percent: 50.0
      },
      clock: %Health.ClockStats{
        offset_ms: 5,
        synchronized: true,
        source: "chrony"
      },
      system: %Health.SystemStats{
        uptime_seconds: 7_200,
        cpu_percent: 20.0,
        cpu_count: 4,
        memory_total_bytes: 8_000_000_000,
        memory_used_bytes: 2_000_000_000,
        memory_used_percent: 25.0,
        disk_path: "/",
        disk_total_bytes: 100_000_000_000,
        disk_used_percent: 40.0,
        health: "ok",
        kernel_release: "6.8.0-ravenwire",
        capture_interface: "ens16f1",
        nic_driver: "ixgbe",
        af_packet_available: true
      }
    }
  end
end
