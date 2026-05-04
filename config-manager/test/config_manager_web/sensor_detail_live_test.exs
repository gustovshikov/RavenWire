defmodule ConfigManagerWeb.SensorDetailLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Auth, Repo, SensorPod}
  alias ConfigManager.Health.Registry

  defp login(conn, role \\ "platform-admin") do
    username = "sensor-detail-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, _user} =
      Auth.create_user(%{
        username: username,
        display_name: "Sensor Detail User",
        role: role,
        password: password
      })

    post(conn, "/login", %{"username" => username, "password" => password})
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
    assert response =~ "Max Drop"
    refute response =~ "Capture Consumers"
  end

  defp health_report(pod_name) do
    %Health.HealthReport{
      sensor_pod_id: pod_name,
      timestamp_unix_ms: DateTime.utc_now() |> DateTime.to_unix(:millisecond),
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
