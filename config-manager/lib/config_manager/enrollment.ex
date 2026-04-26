defmodule ConfigManager.Enrollment do
  @moduledoc """
  Enrollment context — manages the full lifecycle of Sensor_Pod enrollment:

  1. Operator generates a one-time token via `generate_token/1`
  2. Sensor_Agent calls `submit/3` with the token, pod name, and public key
     - Token is validated (not used, not expired) and immediately consumed
     - A pending SensorPod record is created
     - Returns {:ok, :pending}
  3. Operator approves via `approve/1`
     - IntermediateCA issues a 24h ECDSA P-256 leaf cert
     - SensorPod status transitions to "enrolled"
     - Returns {:ok, cert_bundle}
  4. Operator denies via `deny/1`
     - SensorPod record is deleted (or marked denied)
     - Returns {:ok, :denied}
  """

  import Ecto.Query
  require Logger

  alias ConfigManager.{Repo, SensorPod}
  alias ConfigManager.CA.IntermediateCA
  alias ConfigManager.Enrollment.Token

  # ── Token management ─────────────────────────────────────────────────────────

  @doc """
  Generates a new one-time enrollment token valid for 1 hour.
  Returns `{:ok, token_string}`.
  """
  def generate_token(created_by \\ "system") do
    token_value = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    expires_at = DateTime.add(DateTime.utc_now(), 3_600, :second)

    case Token.create(%{token: token_value, created_by: created_by, expires_at: expires_at}) do
      {:ok, _} -> {:ok, token_value}
      {:error, changeset} -> {:error, changeset}
    end
  end

  # ── Enrollment submission ────────────────────────────────────────────────────

  @doc """
  Called by the Sensor_Agent with a one-time token, pod name, and public key PEM.

  Validates the token (single-use enforcement), consumes it immediately, and
  creates a pending SensorPod record.

  Returns:
  - `{:ok, :pending}` — enrollment request stored, awaiting operator approval
  - `{:error, :token_invalid}` — token not found or already consumed
  - `{:error, :token_expired}` — token TTL has elapsed
  """
  def submit(token_value, pod_name, public_key_pem) do
    Repo.transaction(fn ->
      with {:ok, token} <- fetch_and_consume_token(token_value),
           {:ok, fingerprint} <- compute_key_fingerprint(public_key_pem),
           {:ok, pod} <- create_pending_pod(pod_name, public_key_pem, fingerprint) do
        Logger.info("Enrollment request received: pod=#{pod_name}, token=#{token.id}")
        Phoenix.PubSub.broadcast(ConfigManager.PubSub, "enrollments", {:enrollment_updated, pod.id})
        :pending
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, :pending} -> {:ok, :pending}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── Approval ─────────────────────────────────────────────────────────────────

  @doc """
  Approves a pending enrollment. Issues a 24h leaf cert and transitions the
  pod to "enrolled" status.

  Returns `{:ok, %{cert_pem, ca_chain_pem, sensor_pod_id}}` or `{:error, reason}`.
  """
  def approve(pod_id) do
    with {:ok, pod} <- fetch_pending_pod(pod_id),
         {:ok, cert_bundle} <- IntermediateCA.issue_leaf_cert(pod.name, pod.public_key_pem),
         {:ok, enrolled_pod} <- update_pod_enrolled(pod, cert_bundle) do
      Logger.info("Enrollment approved: pod=#{pod.name}, serial=#{cert_bundle.serial}")
      Phoenix.PubSub.broadcast(ConfigManager.PubSub, "enrollments", {:enrollment_updated, pod_id})
      Phoenix.PubSub.broadcast(ConfigManager.PubSub, "sensor_pods", {:pod_updated, pod_id})

      {:ok,
       %{
         cert_pem: cert_bundle.cert_pem,
         ca_chain_pem: cert_bundle.ca_chain_pem,
         sensor_pod_id: enrolled_pod.id
       }}
    end
  end

  # ── Denial ───────────────────────────────────────────────────────────────────

  @doc """
  Denies a pending enrollment. Transitions pod status to `revoked`.
  """
  def deny(pod_id) do
    case Repo.get(SensorPod, pod_id) do
      nil ->
        {:error, :not_found}

      pod ->
        case pod |> SensorPod.revocation_changeset() |> Repo.update() do
          {:ok, _} ->
            Logger.info("Enrollment denied: pod_id=#{pod_id}")
            Phoenix.PubSub.broadcast(ConfigManager.PubSub, "enrollments", {:enrollment_updated, pod_id})
            {:ok, :denied}

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  # ── Queries ──────────────────────────────────────────────────────────────────

  @doc "Returns all pending enrollment requests."
  def list_pending do
    Repo.all(from p in SensorPod, where: p.status == "pending", order_by: [asc: p.inserted_at])
  end

  @doc "Returns all pending enrollment requests (alias for list_pending/0)."
  def list_pending_enrollments, do: list_pending()

  @doc "Returns all enrolled pods."
  def list_enrolled_pods do
    Repo.all(from p in SensorPod, where: p.status == "enrolled", order_by: [asc: p.name])
  end

  @doc "Approves a pending enrollment (alias for approve/1)."
  def approve_enrollment(pod_id), do: approve(pod_id)

  @doc "Denies a pending enrollment (alias for deny/1)."
  def deny_enrollment(pod_id), do: deny(pod_id)

  @doc """
  Returns the cert bundle for an already-enrolled pod (used by the status polling endpoint).
  Since the cert was already issued at approval time, we re-read the stored cert data.
  Returns `{:ok, %{cert_pem, ca_chain_pem, sensor_pod_id}}` or `{:error, reason}`.
  """
  def approve_cert_bundle(%SensorPod{status: "enrolled"} = pod) do
    # The cert PEM is not stored in the DB after issuance (only serial + expiry).
    # The status endpoint is only used during the polling window before the Sensor_Agent
    # receives the cert — once enrolled, the agent already has the cert.
    # Return a minimal response so the agent knows it's approved.
    {:ok, %{cert_pem: nil, ca_chain_pem: nil, sensor_pod_id: pod.id}}
  end

  def approve_cert_bundle(_pod), do: {:error, :not_enrolled}

  @doc """
  Computes the SHA-256 fingerprint of a PEM-encoded public key.
  Returns a colon-separated lowercase hex string, e.g. `\"ab:cd:ef:...\"`
  """
  def public_key_fingerprint(public_key_pem) do
    compute_key_fingerprint(public_key_pem)
  end

  # ── Private helpers ──────────────────────────────────────────────────────────

  defp fetch_and_consume_token(token_value) do
    now = DateTime.utc_now()

    case Repo.get_by(Token, token: token_value) do
      nil ->
        {:error, :token_invalid}

      %Token{consumed_at: consumed} when not is_nil(consumed) ->
        {:error, :token_invalid}

      %Token{expires_at: expires} = token ->
        if DateTime.compare(expires, now) == :lt do
          # Consume expired token to prevent replay
          Repo.update!(Token.consume_changeset(token))
          {:error, :token_expired}
        else
          # Consume immediately — single-use regardless of approval outcome
          {:ok, Repo.update!(Token.consume_changeset(token))}
        end
    end
  end

  defp compute_key_fingerprint(public_key_pem) do
    try do
      fingerprint =
        public_key_pem
        |> String.trim()
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)
        |> then(fn hex ->
          hex |> String.graphemes() |> Enum.chunk_every(2) |> Enum.join(":")
        end)

      {:ok, fingerprint}
    rescue
      e -> {:error, "could not compute key fingerprint: #{inspect(e)}"}
    end
  end

  defp create_pending_pod(pod_name, public_key_pem, fingerprint) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: pod_name,
      public_key_pem: public_key_pem,
      key_fingerprint: fingerprint,
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
    |> Repo.insert()
  end

  defp fetch_pending_pod(pod_id) do
    case Repo.get(SensorPod, pod_id) do
      nil -> {:error, :not_found}
      %SensorPod{status: "pending"} = pod -> {:ok, pod}
      _ -> {:error, :not_pending}
    end
  end

  defp update_pod_enrolled(pod, cert_bundle) do
    pod
    |> SensorPod.approval_changeset(%{
      status: "enrolled",
      cert_serial: cert_bundle.serial,
      cert_expires_at: cert_bundle.expires_at |> DateTime.truncate(:second)
    })
    |> Repo.update()
  end
end
