defmodule ConfigManagerWeb.ApiPcapControllerTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Pcap.CarveRequest
  alias ConfigManager.{AuditEntry, Auth, Repo, SensorPod}

  test "PCAP carve API persists a failed request when the sensor is unreachable" do
    {raw_token, token_name} = create_api_token!(["pcap:search"])
    pod = insert_sensor!("api-pcap-unreachable")

    conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/pcap/carve", %{
        "pod_id" => pod.id,
        "search_type" => "community_id",
        "community_id" => "1:abcdef0123456789="
      })

    body = json_response(conn, 503)
    assert body["error"]["code"] == "SENSOR_UNREACHABLE"
    assert body["data"]["status"] == "failed"
    assert body["data"]["sensor_pod_id"] == pod.id

    request = Repo.get!(CarveRequest, body["data"]["id"])
    assert request.actor == token_name
    assert request.actor_type == "api_token"
    assert request.error_reason == "sensor_unreachable"

    assert Repo.get_by!(AuditEntry, action: "pcap_search", target_id: pod.id)
    assert Repo.get_by!(AuditEntry, action: "pcap_carve_failed", target_id: request.id)
  end

  test "PCAP request list, detail, and manifest endpoints return persisted records" do
    {raw_token, _token_name} = create_api_token!(["pcap:search"])
    pod = insert_sensor!("api-pcap-list")

    carve_conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/pcap/carve", %{
        "pod_id" => pod.id,
        "search_type" => "alert_id",
        "alert_id" => "2400001"
      })

    request_id = json_response(carve_conn, 503)["data"]["id"]

    list_conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/pcap/requests")

    list_body = json_response(list_conn, 200)
    assert Enum.any?(list_body["data"], &(&1["id"] == request_id))
    assert list_body["meta"]["total_count"] >= 1

    detail_conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/pcap/requests/#{request_id}")

    assert json_response(detail_conn, 200)["data"]["id"] == request_id

    manifest_conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/pcap/requests/#{request_id}/manifest")

    manifest = json_response(manifest_conn, 200)
    assert manifest["request"]["id"] == request_id
    assert manifest["integrity_hash"] =~ ~r/^[a-f0-9]{64}$/
    assert Repo.get_by!(AuditEntry, action: "pcap_manifest_export", target_id: request_id)
  end

  test "PCAP carve API returns field validation errors" do
    {raw_token, _token_name} = create_api_token!(["pcap:search"])

    conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/pcap/carve", %{"search_type" => "community_id"})

    body = json_response(conn, 422)
    assert body["error"]["code"] == "VALIDATION_FAILED"
    assert body["error"]["details"]["fields"]["pod_id"] == ["is required"]
  end

  test "PCAP download API reports not ready instead of leaking sensor access" do
    {search_token, _token_name} = create_api_token!(["pcap:search"])
    {download_token, _download_token_name} = create_api_token!(["pcap:download"])
    pod = insert_sensor!("api-pcap-download")

    carve_conn =
      build_conn()
      |> bearer(search_token)
      |> post("/api/v1/pcap/carve", %{
        "pod_id" => pod.id,
        "search_type" => "zeek_uid",
        "zeek_uid" => "Cabc123"
      })

    request_id = json_response(carve_conn, 503)["data"]["id"]

    conn =
      build_conn()
      |> bearer(download_token)
      |> get("/api/v1/pcap/requests/#{request_id}/download")

    assert json_response(conn, 409)["error"]["code"] == "PCAP_NOT_READY"
  end

  defp create_api_token!(permissions) do
    username = "api-pcap-user-#{System.unique_integer([:positive])}"
    token_name = "api-pcap-token-#{System.unique_integer([:positive])}"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: username,
        role: "platform-admin",
        password: "long-enough-password"
      })

    {:ok, _token, raw_token} =
      Auth.create_api_token(user, %{name: token_name, permissions: permissions}, user)

    {raw_token, token_name}
  end

  defp bearer(conn, raw_token), do: put_req_header(conn, "authorization", "Bearer #{raw_token}")

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
      cert_expires_at: DateTime.add(now, 24 * 60 * 60, :second)
    })
    |> Repo.update!()
  end
end
