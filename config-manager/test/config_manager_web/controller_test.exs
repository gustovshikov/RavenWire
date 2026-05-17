defmodule ConfigManagerWeb.ControllerTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Repo, SensorPod}
  alias ConfigManager.Health.Registry

  test "health controller returns health report or not found", %{conn: conn} do
    Registry.update("controller-health-pod", %Health.HealthReport{
      sensor_pod_id: "controller-health-pod",
      timestamp_unix_ms: DateTime.utc_now() |> DateTime.to_unix(:millisecond)
    })

    Process.sleep(50)

    conn = ConfigManagerWeb.HealthController.show(conn, %{"pod_id" => "controller-health-pod"})
    assert json_response(conn, 200)["sensor_pod_id"] == "controller-health-pod"

    conn = ConfigManagerWeb.HealthController.show(build_conn(), %{"pod_id" => "missing"})
    assert json_response(conn, 404)["error"]["code"] == "NOT_FOUND"
  end

  test "enrollment controller reports missing required fields", %{conn: conn} do
    conn = post(conn, "/api/v1/enroll", %{"token" => "only-token"})
    assert json_response(conn, 400)["error"]["code"] == "MISSING_FIELDS"
  end

  test "cert rotation reports missing required fields", %{conn: conn} do
    conn = post(conn, "/api/v1/certs/rotate", %{"pod_name" => "sensor"})
    assert json_response(conn, 400)["error"]["code"] == "MISSING_FIELDS"
  end

  test "support bundle download requires path and enrolled pod", %{conn: conn} do
    enrolled = insert_sensor!("controller-support-pod")

    conn = ConfigManagerWeb.SupportBundleController.download(conn, %{"pod_id" => enrolled.id})
    assert json_response(conn, 400)["error"] =~ "Missing required parameter"

    conn =
      ConfigManagerWeb.SupportBundleController.download(build_conn(), %{
        "pod_id" => Ecto.UUID.generate(),
        "path" => "/tmp/bundle.tar.gz"
      })

    assert json_response(conn, 404)["error"] =~ "Pod not found"
  end

  test "CRL controller returns current CRL bytes", %{conn: conn} do
    conn = ConfigManagerWeb.CRLController.show(conn, %{})
    assert response(conn, 200)
    assert [content_type] = get_resp_header(conn, "content-type")
    assert String.starts_with?(content_type, "application/pkix-crl")
  end

  defp insert_sensor!(name) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled")
    |> Repo.update!()
  end
end
