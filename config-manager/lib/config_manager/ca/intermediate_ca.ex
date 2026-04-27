defmodule ConfigManager.CA.IntermediateCA do
  @moduledoc """
  Manages the Intermediate CA keypair used to issue 24h ECDSA P-256 leaf
  certificates to Sensor_Pods during enrollment.

  On first boot the CA keypair is generated and persisted to the configured
  CA path (default /data/ca). On subsequent boots the existing keypair is
  loaded from disk.

  The CA is a GenServer so callers can issue certs without worrying about
  concurrent access to the private key.
  """

  use GenServer
  require Logger

  alias X509.Certificate
  alias X509.PrivateKey

  @cert_validity_hours 24
  @ca_cert_validity_days 3650  # 10 years for the intermediate CA itself

  # ── Public API ──────────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Issues a 24h ECDSA P-256 leaf certificate for a Sensor_Pod.

  `public_key_pem` is the PEM-encoded ECDSA P-256 public key submitted by
  the Sensor_Agent during enrollment.

  Returns `{:ok, %{cert_pem: ..., ca_chain_pem: ..., serial: ...}}` or
  `{:error, reason}`.
  """
  def issue_leaf_cert(pod_name, public_key_pem) do
    GenServer.call(__MODULE__, {:issue_leaf_cert, pod_name, public_key_pem})
  end

  @doc "Returns the CA certificate chain PEM for distribution."
  def ca_chain_pem do
    GenServer.call(__MODULE__, :ca_chain_pem)
  end

  @doc "Returns the CA certificate (X509.Certificate struct)."
  def ca_cert do
    GenServer.call(__MODULE__, :ca_cert)
  end

  # ── GenServer callbacks ──────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    ca_path = Application.get_env(:config_manager, :ca_path, "/data/ca")
    File.mkdir_p!(ca_path)

    state = load_or_generate_ca(ca_path)
    Logger.info("IntermediateCA ready. Subject: #{inspect(Certificate.subject(state.ca_cert))}")
    {:ok, state}
  end

  @impl true
  def handle_call({:issue_leaf_cert, pod_name, public_key_pem}, _from, state) do
    result = do_issue_leaf_cert(pod_name, public_key_pem, state)
    {:reply, result, state}
  end

  def handle_call(:ca_chain_pem, _from, state) do
    {:reply, state.ca_chain_pem, state}
  end

  def handle_call(:ca_cert, _from, state) do
    {:reply, state.ca_cert, state}
  end

  # ── Private helpers ──────────────────────────────────────────────────────────

  defp load_or_generate_ca(ca_path) do
    key_path = Path.join(ca_path, "intermediate-ca.key.pem")
    cert_path = Path.join(ca_path, "intermediate-ca.cert.pem")

    if File.exists?(key_path) and File.exists?(cert_path) do
      Logger.info("Loading existing Intermediate CA from #{ca_path}")
      key = key_path |> File.read!() |> PrivateKey.from_pem!()
      cert = cert_path |> File.read!() |> Certificate.from_pem!()
      %{ca_key: key, ca_cert: cert, ca_chain_pem: File.read!(cert_path), ca_path: ca_path}
    else
      Logger.info("Generating new Intermediate CA keypair at #{ca_path}")
      generate_ca(ca_path, key_path, cert_path)
    end
  end

  defp generate_ca(ca_path, key_path, cert_path) do
    key = PrivateKey.new_ec(:secp256r1)

    not_before = DateTime.utc_now()
    not_after = DateTime.add(not_before, @ca_cert_validity_days * 86_400, :second)

    cert =
      X509.Certificate.self_signed(
        key,
        "/CN=RavenWire Manager Intermediate CA/O=RavenWire",
        template: :ca,
        validity: X509.Certificate.Validity.new(not_before, not_after)
      )

    key_pem = PrivateKey.to_pem(key)
    cert_pem = Certificate.to_pem(cert)

    # Write with restricted permissions — private key must not be world-readable
    File.write!(key_path, key_pem)
    File.chmod!(key_path, 0o600)
    File.write!(cert_path, cert_pem)

    Logger.info("Intermediate CA generated and saved to #{ca_path}")
    %{ca_key: key, ca_cert: cert, ca_chain_pem: cert_pem, ca_path: ca_path}
  end

  defp do_issue_leaf_cert(pod_name, public_key_pem, state) do
    with {:ok, public_key} <- decode_public_key(public_key_pem) do
      serial = :crypto.strong_rand_bytes(16) |> :binary.decode_unsigned()

      not_before = DateTime.utc_now()
      not_after = DateTime.add(not_before, @cert_validity_hours * 3_600, :second)

      cert =
        X509.Certificate.new(
          public_key,
          "/CN=#{pod_name}/O=RavenWire/OU=Sensor Pod",
          state.ca_cert,
          state.ca_key,
          serial: serial,
          validity: X509.Certificate.Validity.new(not_before, not_after),
          extensions: [
            subject_alt_name: X509.Certificate.Extension.subject_alt_name([pod_name]),
            key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyEncipherment]),
            ext_key_usage: X509.Certificate.Extension.ext_key_usage([:clientAuth])
          ]
        )

      cert_pem = Certificate.to_pem(cert)

      {:ok,
       %{
         cert_pem: cert_pem,
         ca_chain_pem: state.ca_chain_pem,
         serial: Integer.to_string(serial, 16),
         expires_at: not_after
       }}
    end
  end

  defp decode_public_key(pem) do
    try do
      key = X509.PublicKey.from_pem!(pem)
      {:ok, key}
    rescue
      e -> {:error, "invalid public key PEM: #{inspect(e)}"}
    end
  end
end
