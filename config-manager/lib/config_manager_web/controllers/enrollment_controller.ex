defmodule ConfigManagerWeb.EnrollmentController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Enrollment

  # POST /api/v1/enroll
  # Called by Sensor_Agent on first boot with SENSOR_ENROLLMENT_TOKEN set.
  # Validates the one-time token, stores a pending enrollment, returns 202.
  def create(conn, params) do
    with {:ok, token} <- Map.fetch(params, "token"),
         {:ok, pod_name} <- Map.fetch(params, "pod_name"),
         {:ok, public_key_pem} <- Map.fetch(params, "public_key") do
      case Enrollment.submit(token, pod_name, public_key_pem) do
        {:ok, {:approved, cert_bundle}} ->
          # AUTO_ENROLL_FIRST — cert issued immediately, return 200 with cert
          conn
          |> put_status(200)
          |> json(%{
            status: "approved",
            cert_pem: cert_bundle.cert_pem,
            ca_chain_pem: cert_bundle.ca_chain_pem,
            sensor_pod_id: cert_bundle.sensor_pod_id
          })

        {:ok, :pending} ->
          conn
          |> put_status(202)
          |> json(%{status: "pending", message: "Enrollment request received; awaiting operator approval"})

        {:error, :token_invalid} ->
          conn
          |> put_status(401)
          |> json(%{error: %{code: "TOKEN_INVALID", message: "Enrollment token is invalid or has already been used"}})

        {:error, :token_expired} ->
          conn
          |> put_status(401)
          |> json(%{error: %{code: "TOKEN_EXPIRED", message: "Enrollment token has expired"}})

        {:error, reason} ->
          conn
          |> put_status(422)
          |> json(%{error: %{code: "ENROLLMENT_FAILED", message: inspect(reason)}})
      end
    else
      :error ->
        conn
        |> put_status(400)
        |> json(%{error: %{code: "MISSING_FIELDS", message: "token, pod_name, and public_key are required"}})
    end
  end

  # GET /api/v1/enroll/status?pod_name=<name>
  # Polled by Sensor_Agent while waiting for operator approval.
  # Returns 200 + cert bundle if approved, 202 if still pending, 404 if not found.
  def status(conn, %{"pod_name" => pod_name}) do
    import Ecto.Query
    alias ConfigManager.{Repo, SensorPod}

    case Repo.one(from p in SensorPod, where: p.name == ^pod_name, order_by: [desc: p.inserted_at], limit: 1) do
      nil ->
        conn
        |> put_status(404)
        |> json(%{error: %{code: "NOT_FOUND", message: "No enrollment record found for pod #{pod_name}"}})

      %SensorPod{status: "enrolled"} = pod ->
        # Approved — return cert bundle
        case ConfigManager.Enrollment.approve_cert_bundle(pod) do
          {:ok, cert_bundle} ->
            json(conn, %{
              status: "approved",
              cert_pem: cert_bundle.cert_pem,
              ca_chain_pem: cert_bundle.ca_chain_pem,
              sensor_pod_id: cert_bundle.sensor_pod_id
            })

          {:error, _reason} ->
            # Already enrolled, return pod id with a note that cert was already issued
            json(conn, %{
              status: "approved",
              sensor_pod_id: pod.id
            })
        end

      %SensorPod{status: "pending"} ->
        conn
        |> put_status(202)
        |> json(%{status: "pending", message: "Enrollment request is awaiting operator approval"})

      %SensorPod{status: "revoked"} ->
        conn
        |> put_status(403)
        |> json(%{error: %{code: "ENROLLMENT_DENIED", message: "Enrollment request was denied"}})
    end
  end

  def status(conn, _params) do
    conn
    |> put_status(400)
    |> json(%{error: %{code: "MISSING_FIELDS", message: "pod_name query parameter is required"}})
  end

  # POST /api/v1/enrollment/:id/approve  (mTLS-authenticated operator action)
  def approve(conn, %{"id" => id}) do
    case Enrollment.approve(id) do
      {:ok, cert_bundle} ->
        json(conn, %{
          status: "approved",
          cert_pem: cert_bundle.cert_pem,
          ca_chain_pem: cert_bundle.ca_chain_pem,
          sensor_pod_id: cert_bundle.sensor_pod_id
        })

      {:error, :not_found} ->
        conn |> put_status(404) |> json(%{error: %{code: "NOT_FOUND", message: "Enrollment request not found"}})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: %{code: "APPROVAL_FAILED", message: inspect(reason)}})
    end
  end

  # POST /api/v1/enrollment/:id/deny  (mTLS-authenticated operator action)
  def deny(conn, %{"id" => id}) do
    case Enrollment.deny(id) do
      {:ok, _} ->
        json(conn, %{status: "denied"})

      {:error, :not_found} ->
        conn |> put_status(404) |> json(%{error: %{code: "NOT_FOUND", message: "Enrollment request not found"}})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: %{code: "DENIAL_FAILED", message: inspect(reason)}})
    end
  end
end
