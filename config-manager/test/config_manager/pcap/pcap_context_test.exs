defmodule ConfigManager.Pcap.ContextTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Pcap
  alias ConfigManager.Pcap.CustodyEvent
  alias ConfigManager.{AuditEntry, Auth, Repo, SensorPod}

  defmodule MockClient do
    def request_pcap_carve(_pod, _payload), do: {:ok, %{"status" => "queued"}}

    def download_pcap_carve(_pod, _request_id) do
      {:ok, %{body: <<0xD4, 0xC3, 0xB2, 0xA1>>, content_type: "application/vnd.tcpdump.pcap"}}
    end
  end

  test "submit_carve creates and dispatches a request through the sensor client" do
    actor = insert_user!("pcap-dispatch-user")
    pod = insert_sensor!("pcap-dispatch-sensor", control_api_host: "127.0.0.1")

    assert {:ok, request} =
             Pcap.submit_carve(
               %{
                 "pod_id" => pod.id,
                 "search_type" => "community_id",
                 "community_id" => "1:abcdef0123456789="
               },
               actor,
               MockClient
             )

    assert request.status == "dispatched"
    assert request.actor == actor.username
    assert request.actor_type == "user"
    assert request.sensor_pod_id == pod.id

    assert Repo.get_by!(AuditEntry, action: "pcap_search", target_id: pod.id)
    assert Repo.get_by!(AuditEntry, action: "pcap_carve_dispatch", target_id: request.id)
  end

  test "submit_carve marks requests failed when the sensor has no control API host" do
    actor = insert_user!("pcap-unreachable-user")
    pod = insert_sensor!("pcap-unreachable-sensor")

    assert {:error, {:sensor_unreachable, request}} =
             Pcap.submit_carve(
               %{
                 "pod_id" => pod.id,
                 "search_type" => "time_range",
                 "start_time" =>
                   DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.to_iso8601(),
                 "end_time" => DateTime.utc_now() |> DateTime.to_iso8601()
               },
               actor
             )

    assert request.status == "failed"
    assert request.error_reason == "sensor_unreachable"
    assert Repo.get_by!(AuditEntry, action: "pcap_carve_failed", target_id: request.id)
  end

  test "completed requests create custody manifests and can be downloaded" do
    actor = insert_user!("pcap-complete-user")
    pod = insert_sensor!("pcap-complete-sensor", control_api_host: "127.0.0.1")

    {:ok, request} =
      Pcap.submit_carve(
        %{
          "pod_id" => pod.id,
          "search_type" => "alert_id",
          "alert_id" => "2400001"
        },
        actor,
        MockClient
      )

    {:ok, carving} = Pcap.update_status(request, "carving")

    {:ok, completed} =
      Pcap.update_status(carving, "completed", %{
        file_path: "/sensor/pcap/alerts/request.pcap",
        file_size_bytes: 4,
        sha256: "a" <> String.duplicate("0", 63),
        packet_count: 1,
        time_span_start:
          DateTime.utc_now() |> DateTime.add(-10, :second) |> DateTime.to_iso8601(),
        time_span_end: DateTime.utc_now() |> DateTime.to_iso8601()
      })

    assert completed.status == "completed"
    assert completed.expires_at
    assert Repo.get_by!(CustodyEvent, carve_request_id: completed.id, event_type: "created")
    assert Repo.get_by!(AuditEntry, action: "pcap_carve_complete", target_id: completed.id)

    manifest = Pcap.manifest(completed)
    assert manifest.request.id == completed.id
    assert manifest.integrity_hash =~ ~r/^[a-f0-9]{64}$/

    assert {:ok, download} = Pcap.download_pcap(completed, actor, "127.0.0.1", MockClient)
    assert download.body == <<0xD4, 0xC3, 0xB2, 0xA1>>
    assert download.filename =~ "pcap-complete-sensor-alert_id-"
    assert Repo.get_by!(CustodyEvent, carve_request_id: completed.id, event_type: "downloaded")
    assert Repo.get_by!(AuditEntry, action: "pcap_download", target_id: completed.id)
  end

  test "validation rejects missing pod and oversized time ranges" do
    actor = insert_user!("pcap-validation-user")

    assert {:error, {:validation, %{pod_id: ["is required"]}}} =
             Pcap.submit_carve(%{"search_type" => "community_id"}, actor)

    pod = insert_sensor!("pcap-validation-sensor")

    start_time =
      DateTime.utc_now() |> DateTime.add(-25 * 60 * 60, :second) |> DateTime.to_iso8601()

    end_time = DateTime.utc_now() |> DateTime.to_iso8601()

    assert {:error, {:validation, errors}} =
             Pcap.submit_carve(
               %{
                 "pod_id" => pod.id,
                 "search_type" => "time_range",
                 "start_time" => start_time,
                 "end_time" => end_time
               },
               actor
             )

    assert "range exceeds 24 hours" in errors["end_time"]
  end

  defp insert_user!(username) do
    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: username,
        role: "analyst",
        password: "long-enough-password"
      })

    user
  end

  defp insert_sensor!(name, opts \\ []) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: now,
      enrolled_by: "tester",
      control_api_host: Keyword.get(opts, :control_api_host)
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(%{
      status: "enrolled",
      cert_serial: "#{name}-serial",
      cert_expires_at: DateTime.add(now, 24 * 60 * 60, :second)
    })
    |> Repo.update!()
  end
end
