defmodule ConfigManager.SensorPod do
  @moduledoc """
  Ecto schema for a Sensor_Pod identity record.

  Tracks enrollment state, certificate lifecycle, and pool membership.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_statuses ~w(pending enrolled revoked)

  schema "sensor_pods" do
    field(:name, :string)
    field(:pool_id, :binary_id)
    field(:status, :string, default: "pending")
    field(:cert_serial, :string)
    field(:cert_expires_at, :utc_datetime)
    field(:last_seen_at, :utc_datetime)
    field(:enrolled_at, :utc_datetime)
    field(:enrolled_by, :string)
    # Stored during enrollment request; cleared after cert issuance
    field(:public_key_pem, :string)
    # SHA-256 fingerprint of the public key for display in the approval UI
    field(:key_fingerprint, :string)

    # Issued cert PEM — stored at approval time so the status endpoint can return it
    field(:cert_pem, :string)
    field(:ca_chain_pem, :string)

    # Control API host for dispatching mode changes to the Sensor_Agent
    field(:control_api_host, :string)

    # Alert-Driven PCAP configuration (Requirements: 10.5, 10.6, 10.7)
    field(:pcap_ring_size_mb, :integer, default: 4096)
    field(:pre_alert_window_sec, :integer, default: 60)
    field(:post_alert_window_sec, :integer, default: 30)
    # 1=low, 2=medium, 3=high
    field(:alert_severity_threshold, :integer, default: 2)

    timestamps()
  end

  @doc "Changeset for creating a new pending enrollment."
  def enrollment_changeset(pod, attrs) do
    pod
    |> cast(attrs, [:name, :public_key_pem, :key_fingerprint, :enrolled_at, :enrolled_by])
    |> validate_required([:name, :public_key_pem, :key_fingerprint])
    |> validate_length(:name, min: 1, max: 255)
    |> unique_constraint(:name)
  end

  @doc "Changeset for replacing an existing pod identity with a fresh pending enrollment."
  def reenrollment_changeset(pod, attrs) do
    pod
    |> cast(attrs, [:name, :public_key_pem, :key_fingerprint, :enrolled_at, :enrolled_by])
    |> validate_required([:name, :public_key_pem, :key_fingerprint])
    |> validate_length(:name, min: 1, max: 255)
    |> change(
      status: "pending",
      cert_serial: nil,
      cert_expires_at: nil,
      cert_pem: nil,
      ca_chain_pem: nil
    )
  end

  @doc "Changeset for approving an enrollment and recording the issued cert."
  def approval_changeset(pod, attrs) do
    pod
    |> cast(attrs, [
      :status,
      :cert_serial,
      :cert_expires_at,
      :enrolled_by,
      :cert_pem,
      :ca_chain_pem
    ])
    |> validate_required([:status, :cert_serial, :cert_expires_at])
    |> validate_inclusion(:status, @valid_statuses)
  end

  @doc "Changeset for replacing an enrolled pod certificate during rotation."
  def cert_rotation_changeset(pod, attrs) do
    pod
    |> cast(attrs, [
      :status,
      :public_key_pem,
      :key_fingerprint,
      :cert_serial,
      :cert_expires_at,
      :cert_pem,
      :ca_chain_pem
    ])
    |> validate_required([
      :status,
      :public_key_pem,
      :key_fingerprint,
      :cert_serial,
      :cert_expires_at,
      :cert_pem,
      :ca_chain_pem
    ])
    |> validate_inclusion(:status, @valid_statuses)
  end

  @doc "Changeset for updating last_seen_at from health stream."
  def heartbeat_changeset(pod, attrs) do
    pod
    |> cast(attrs, [:last_seen_at])
    |> validate_required([:last_seen_at])
  end

  @doc "Changeset for revoking a pod."
  def revocation_changeset(pod) do
    change(pod, status: "revoked")
  end

  @doc "Changeset for updating Alert-Driven PCAP configuration."
  def pcap_config_changeset(pod, attrs) do
    pod
    |> cast(attrs, [
      :pcap_ring_size_mb,
      :pre_alert_window_sec,
      :post_alert_window_sec,
      :alert_severity_threshold
    ])
    |> validate_required([
      :pcap_ring_size_mb,
      :pre_alert_window_sec,
      :post_alert_window_sec,
      :alert_severity_threshold
    ])
    |> validate_number(:pcap_ring_size_mb, greater_than: 0)
    |> validate_number(:pre_alert_window_sec, greater_than_or_equal_to: 0)
    |> validate_number(:post_alert_window_sec, greater_than_or_equal_to: 0)
    |> validate_inclusion(:alert_severity_threshold, [1, 2, 3])
  end
end
