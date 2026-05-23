defmodule ConfigManagerWeb.PcapLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Pcap
  alias ConfigManager.Pcap.CommunityId
  alias ConfigManager.{Auth, Repo, SensorPod}

  test "PCAP search page renders for analysts and denies viewers", %{conn: conn} do
    {analyst_conn, _analyst} = login(conn, "analyst")

    response =
      analyst_conn
      |> recycle()
      |> get("/pcap")
      |> html_response(200)

    assert response =~ "PCAP Search"
    assert response =~ "Community ID Calculator"

    {viewer_conn, _viewer} = login(conn, "viewer")

    denied =
      viewer_conn
      |> recycle()
      |> get("/pcap")

    assert response(denied, 403) =~ "Forbidden"
  end

  test "PCAP request history, detail, and manifest render scoped records", %{conn: conn} do
    {analyst_conn, analyst} = login(conn, "analyst")
    pod = insert_sensor!("pcap-live-sensor")

    {:error, {:sensor_unreachable, request}} =
      Pcap.submit_carve(
        %{
          "pod_id" => pod.id,
          "search_type" => "community_id",
          "community_id" => community_id()
        },
        analyst
      )

    history =
      analyst_conn
      |> recycle()
      |> get("/pcap/requests")
      |> html_response(200)

    assert history =~ "PCAP Requests"
    assert history =~ "pcap-live-sensor"

    detail =
      analyst_conn
      |> recycle()
      |> get("/pcap/requests/#{request.id}")
      |> html_response(200)

    assert detail =~ "pcap-live-sensor PCAP Request"
    assert detail =~ "sensor_unreachable"

    manifest =
      analyst_conn
      |> recycle()
      |> get("/pcap/requests/#{request.id}/manifest")
      |> html_response(200)

    assert manifest =~ "Chain-of-Custody Manifest"
    assert manifest =~ request.id
  end

  defp login(conn, role) do
    username = "pcap-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "PCAP Live User",
        role: role,
        password: password
      })

    {post(conn, "/login", %{"username" => username, "password" => password}), user}
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
      cert_expires_at: DateTime.add(now, 24 * 60 * 60, :second)
    })
    |> Repo.update!()
  end

  defp community_id do
    CommunityId.compute!(%{
      src_ip: "192.0.2.10",
      dst_ip: "198.51.100.10",
      src_port: 12345,
      dst_port: 443,
      protocol: "tcp"
    })
  end
end
