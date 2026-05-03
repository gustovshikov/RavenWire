defmodule ConfigManagerWeb.CertController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Enrollment

  def rotate(conn, params) do
    with {:ok, pod_name} <- rotation_pod_name(conn, params),
         {:ok, public_key_pem} <- Map.fetch(params, "public_key") do
      case Enrollment.rotate_cert(pod_name, public_key_pem) do
        {:ok, cert_bundle} ->
          json(conn, %{
            status: "approved",
            cert_pem: cert_bundle.cert_pem,
            ca_chain_pem: cert_bundle.ca_chain_pem,
            sensor_pod_id: cert_bundle.sensor_pod_id,
            config_json: cert_bundle.config_json
          })

        {:error, :not_found} ->
          conn
          |> put_status(404)
          |> json(%{error: %{code: "NOT_FOUND", message: "Sensor pod not found"}})

        {:error, :not_enrolled} ->
          conn
          |> put_status(409)
          |> json(%{error: %{code: "NOT_ENROLLED", message: "Sensor pod is not enrolled"}})

        {:error, reason} ->
          conn
          |> put_status(422)
          |> json(%{error: %{code: "ROTATION_FAILED", message: inspect(reason)}})
      end
    else
      :error ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{code: "MISSING_FIELDS", message: "pod_name and public_key are required"}
        })

      {:error, :unauthorized} ->
        conn
        |> put_status(401)
        |> json(%{error: %{code: "UNAUTHORIZED", message: "Client certificate required"}})
    end
  end

  defp rotation_pod_name(conn, params) do
    case peer_common_name(conn) do
      nil ->
        if allow_plain_rotation?() do
          Map.fetch(params, "pod_name")
        else
          {:error, :unauthorized}
        end

      cn ->
        {:ok, cn}
    end
  end

  defp peer_common_name(conn) do
    cert = Map.get(conn.private, :ssl_cert)

    if cert do
      cert
      |> X509.Certificate.subject()
      |> X509.RDNSequence.get_attr(:commonName)
      |> List.first()
      |> then(fn
        nil -> nil
        {_type, value} -> value
      end)
    end
  rescue
    _ -> nil
  end

  defp allow_plain_rotation? do
    Application.get_env(:config_manager, :allow_plain_cert_rotation, false)
  end
end
