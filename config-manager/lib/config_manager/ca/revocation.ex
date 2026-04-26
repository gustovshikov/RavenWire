defmodule ConfigManager.CA.Revocation do
  @moduledoc """
  High-level API for certificate revocation operations.

  Revocation flow:
  1. Operator calls `revoke_pod/2` with a pod ID and reason
  2. The pod's cert serial is looked up and added to the CRL
  3. The pod status is updated to "revoked" in the database
  4. The CRL is rebuilt and re-signed
  5. Connected Sensor_Agents receive the updated CRL via the health stream
     or can fetch it via GET /api/v1/crl

  All TLS connections from revoked identities are rejected at the handshake
  layer by the MTLSAuth plug, which checks the CRLStore ETS table.
  """

  require Logger
  import Ecto.Query

  alias ConfigManager.{Repo, SensorPod}
  alias ConfigManager.CA.CRLStore

  @doc """
  Revokes the certificate for a Sensor_Pod by pod ID.

  Updates pod status to "revoked", adds the cert serial to the CRL, and
  rebuilds the signed CRL.

  Returns `:ok` or `{:error, reason}`.
  """
  def revoke_pod(pod_id, reason \\ :unspecified) do
    case Repo.get(SensorPod, pod_id) do
      nil ->
        {:error, :not_found}

      %SensorPod{cert_serial: nil} ->
        {:error, :no_cert_to_revoke}

      %SensorPod{status: "revoked"} ->
        {:error, :already_revoked}

      pod ->
        Repo.transaction(fn ->
          # Mark pod as revoked in DB
          pod
          |> SensorPod.revocation_changeset()
          |> Repo.update!()

          # Add serial to CRL
          :ok = CRLStore.revoke(pod.cert_serial, reason)

          Logger.info("Pod revoked: pod_id=#{pod_id}, serial=#{pod.cert_serial}, reason=#{reason}")

          Phoenix.PubSub.broadcast(
            ConfigManager.PubSub,
            "sensor_pods",
            {:pod_updated, pod_id}
          )
        end)
        |> case do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, reason}
        end
    end
  end

  @doc """
  Returns all revoked certificate serials from the database.
  Used to rebuild the CRL on startup.
  """
  def list_revoked_serials do
    Repo.all(from r in "revoked_certs", select: r.serial)
  end

  @doc """
  Checks whether a given cert serial is currently revoked.
  Delegates to the ETS-backed CRLStore for O(1) lookup.
  """
  def revoked?(serial), do: CRLStore.is_revoked?(serial)
end
