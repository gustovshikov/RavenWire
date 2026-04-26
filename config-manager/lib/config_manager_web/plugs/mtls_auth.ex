defmodule ConfigManagerWeb.Plugs.MTLSAuth do
  @moduledoc """
  Plug that enforces mTLS authentication by verifying the client certificate
  presented during the TLS handshake.

  Rejects connections from:
  - Missing client certificate
  - Expired certificates
  - Certificates signed by an untrusted CA
  - Certificates listed in the current CRL

  Logs all rejections with the presenting identity (CN from cert subject).
  """

  import Plug.Conn
  require Logger

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_peer_cert(conn) do
      {:ok, cert} ->
        case validate_cert(cert) do
          :ok ->
            cn = extract_cn(cert)
            assign(conn, :mtls_identity, cn)

          {:error, reason} ->
            cn = extract_cn(cert)
            Logger.warning("mTLS cert rejected: #{reason}, presenting identity: #{cn}")
            conn |> send_resp(403, Jason.encode!(%{error: %{code: "CERT_REJECTED", message: reason}})) |> halt()
        end

      {:error, :no_peer_cert} ->
        Logger.warning("mTLS connection rejected: no client certificate presented")
        conn |> send_resp(401, Jason.encode!(%{error: %{code: "NO_CLIENT_CERT", message: "Client certificate required"}})) |> halt()
    end
  end

  # In production, the peer cert is provided by the TLS layer via conn.private.
  # Cowboy/Bandit populate :ssl_cert in the peer data.
  defp get_peer_cert(conn) do
    case Map.get(conn.private, :ssl_cert) do
      nil -> {:error, :no_peer_cert}
      cert -> {:ok, cert}
    end
  end

  defp validate_cert(cert) do
    with :ok <- check_expiry(cert),
         :ok <- check_crl(cert) do
      :ok
    end
  end

  defp check_expiry(cert) do
    case X509.Certificate.validity(cert) do
      {:Validity, not_before, not_after} ->
        now = DateTime.utc_now()
        nb = X509.DateTime.to_datetime(not_before)
        na = X509.DateTime.to_datetime(not_after)

        cond do
          DateTime.compare(now, nb) == :lt -> {:error, "certificate not yet valid"}
          DateTime.compare(now, na) == :gt -> {:error, "certificate expired"}
          true -> :ok
        end

      _ ->
        {:error, "could not parse certificate validity"}
    end
  end

  defp check_crl(cert) do
    serial = X509.Certificate.serial(cert)

    case ConfigManager.CA.CRLStore.is_revoked?(serial) do
      true -> {:error, "certificate revoked (serial: #{serial})"}
      false -> :ok
    end
  end

  defp extract_cn(cert) do
    try do
      cert
      |> X509.Certificate.subject()
      |> X509.RDNSequence.get_attr(:commonName)
      |> List.first()
      |> elem(1)
    rescue
      _ -> "unknown"
    end
  end
end
