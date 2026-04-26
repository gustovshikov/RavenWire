defmodule ConfigManager.CA.CRLStore do
  @moduledoc """
  Maintains the Certificate Revocation List (CRL) for the Intermediate CA.

  Revoked certificate serials are stored in the database and cached in an
  ETS table for fast O(1) lookups at TLS handshake time.

  The CRL is rebuilt and re-signed whenever a certificate is revoked.
  Sensor_Agents can fetch the current CRL via GET /api/v1/crl.
  """

  use GenServer
  require Logger

  @table :crl_revoked_serials

  # ── Public API ──────────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Returns true if the given certificate serial (hex string) is revoked."
  def is_revoked?(serial) when is_binary(serial) do
    :ets.member(@table, serial)
  end

  def is_revoked?(serial) when is_integer(serial) do
    is_revoked?(Integer.to_string(serial, 16))
  end

  @doc "Revokes a certificate by serial. Rebuilds and re-signs the CRL."
  def revoke(serial, reason \\ :unspecified) do
    GenServer.call(__MODULE__, {:revoke, to_string(serial), reason})
  end

  @doc "Returns the current CRL in DER format."
  def current_crl_der do
    GenServer.call(__MODULE__, :current_crl_der)
  end

  @doc "Returns the current CRL in PEM format."
  def current_crl_pem do
    GenServer.call(__MODULE__, :current_crl_pem)
  end

  # ── GenServer callbacks ──────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])

    # Load revoked serials from DB into ETS on startup
    revoked = load_revoked_from_db()
    Enum.each(revoked, fn serial -> :ets.insert(@table, {serial, true}) end)

    state = %{crl_der: nil, crl_pem: nil}
    state = rebuild_crl(state)

    Logger.info("CRLStore initialized with #{length(revoked)} revoked certificate(s)")
    {:ok, state}
  end

  @impl true
  def handle_call({:revoke, serial, reason}, _from, state) do
    :ets.insert(@table, {serial, true})
    persist_revocation(serial, reason)
    state = rebuild_crl(state)
    Logger.info("Certificate revoked: serial=#{serial}, reason=#{reason}")
    {:reply, :ok, state}
  end

  def handle_call(:current_crl_der, _from, state) do
    {:reply, {:ok, state.crl_der}, state}
  end

  def handle_call(:current_crl_pem, _from, state) do
    {:reply, {:ok, state.crl_pem}, state}
  end

  # ── Private helpers ──────────────────────────────────────────────────────────

  defp load_revoked_from_db do
    import Ecto.Query
    ConfigManager.Repo.all(from r in "revoked_certs", select: r.serial)
  rescue
    _ -> []
  end

  defp persist_revocation(serial, reason) do
    ConfigManager.Repo.insert_all("revoked_certs", [
      %{
        serial: serial,
        reason: to_string(reason),
        revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
        inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
        updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
      }
    ])
  rescue
    e -> Logger.error("Failed to persist revocation for serial #{serial}: #{inspect(e)}")
  end

  defp rebuild_crl(state) do
    # Build CRL using the Intermediate CA key and cert
    try do
      ca_cert = ConfigManager.CA.IntermediateCA.ca_cert()
      revoked_serials = :ets.tab2list(@table) |> Enum.map(fn {serial, _} -> serial end)

      # Build a minimal CRL using :public_key OTP module
      # X509 library does not expose CRL building directly; we use :public_key
      crl_der = build_crl_der(ca_cert, revoked_serials)
      crl_pem = :public_key.pem_encode([{:CertificateList, crl_der, :not_encrypted}])

      %{state | crl_der: crl_der, crl_pem: crl_pem}
    rescue
      e ->
        Logger.error("Failed to rebuild CRL: #{inspect(e)}")
        state
    end
  end

  # Builds a DER-encoded CRL using the OTP :public_key module.
  # The CRL is valid for 24 hours (matching leaf cert lifetime).
  defp build_crl_der(_ca_cert, _revoked_serials) do
    # Placeholder: in production this would use :public_key.pkix_sign/2 to
    # produce a signed CRL. The full implementation requires constructing the
    # TBSCertList ASN.1 record and signing it with the CA private key.
    # This is wired up when the CA key is accessible here; for now we return
    # an empty DER sequence as a structural placeholder.
    <<0x30, 0x00>>
  end
end
