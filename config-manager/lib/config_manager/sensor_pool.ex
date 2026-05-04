defmodule ConfigManager.SensorPool do
  @moduledoc """
  Ecto schema for a Sensor_Pool configuration profile.

  A pool groups one or more Sensor_Pods under a shared configuration.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_capture_modes ~w(alert_driven full_pcap)
  @name_format ~r/^[a-zA-Z0-9._-]+$/
  @config_fields [
    :capture_mode,
    :pcap_ring_size_mb,
    :pre_alert_window_sec,
    :post_alert_window_sec,
    :alert_severity_threshold
  ]

  schema "sensor_pools" do
    field(:name, :string)
    field(:description, :string)
    field(:capture_mode, :string, default: "alert_driven")
    field(:config_version, :integer, default: 1)
    field(:config_updated_at, :utc_datetime)
    field(:config_updated_by, :string)
    field(:pcap_ring_size_mb, :integer, default: 4096)
    field(:pre_alert_window_sec, :integer, default: 60)
    field(:post_alert_window_sec, :integer, default: 30)
    field(:alert_severity_threshold, :integer, default: 2)

    timestamps()
  end

  def changeset(pool, attrs) do
    create_changeset(pool, attrs, get_field(change(pool), :config_updated_by) || "system")
  end

  def create_changeset(pool, attrs, actor) do
    pool
    |> cast(attrs, [:name, :description] ++ @config_fields)
    |> normalize_name()
    |> validate_required([:name, :capture_mode])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:name, @name_format,
      message: "must contain only alphanumeric characters, hyphens, underscores, and periods"
    )
    |> validate_inclusion(:capture_mode, @valid_capture_modes)
    |> validate_pcap_fields()
    |> put_change(:config_version, 1)
    |> put_change(:config_updated_at, now_utc())
    |> put_change(:config_updated_by, actor)
    |> unique_constraint(:name,
      name: :sensor_pools_name_nocase_index,
      message: "has already been taken"
    )
    |> unique_constraint(:name,
      name: :sensor_pools_name_index,
      message: "has already been taken"
    )
  end

  def metadata_changeset(pool, attrs) do
    pool
    |> cast(attrs, [:name, :description])
    |> normalize_name()
    |> validate_required([:name])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:name, @name_format,
      message: "must contain only alphanumeric characters, hyphens, underscores, and periods"
    )
    |> unique_constraint(:name,
      name: :sensor_pools_name_nocase_index,
      message: "has already been taken"
    )
    |> unique_constraint(:name,
      name: :sensor_pools_name_index,
      message: "has already been taken"
    )
  end

  def config_update_changeset(pool, attrs, actor \\ "system") do
    pool
    |> cast(attrs, @config_fields)
    |> validate_required([:capture_mode])
    |> validate_inclusion(:capture_mode, @valid_capture_modes)
    |> validate_pcap_fields()
    |> maybe_version_and_metadata(actor)
  end

  defp normalize_name(changeset) do
    update_change(changeset, :name, fn name -> String.trim(to_string(name)) end)
  end

  defp validate_pcap_fields(changeset) do
    changeset
    |> validate_number(:pcap_ring_size_mb, greater_than: 0)
    |> validate_number(:pre_alert_window_sec, greater_than_or_equal_to: 0)
    |> validate_number(:post_alert_window_sec, greater_than_or_equal_to: 0)
    |> validate_inclusion(:alert_severity_threshold, [1, 2, 3])
  end

  defp maybe_version_and_metadata(changeset, actor) do
    if Enum.any?(@config_fields, &Map.has_key?(changeset.changes, &1)) do
      current = get_field(changeset, :config_version) || 1

      changeset
      |> put_change(:config_version, current + 1)
      |> put_change(:config_updated_at, now_utc())
      |> put_change(:config_updated_by, actor)
    else
      changeset
    end
  end

  defp now_utc, do: DateTime.utc_now() |> DateTime.truncate(:second)
end
