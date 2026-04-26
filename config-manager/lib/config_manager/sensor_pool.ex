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

  schema "sensor_pools" do
    field :name, :string
    field :capture_mode, :string, default: "alert_driven"
    field :config_version, :integer, default: 1
    field :config_updated_at, :utc_datetime
    field :config_updated_by, :string

    timestamps()
  end

  def changeset(pool, attrs) do
    pool
    |> cast(attrs, [:name, :capture_mode, :config_version, :config_updated_at, :config_updated_by])
    |> validate_required([:name, :capture_mode])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:capture_mode, @valid_capture_modes)
    |> unique_constraint(:name)
  end

  def config_update_changeset(pool, attrs) do
    pool
    |> cast(attrs, [:capture_mode, :config_updated_at, :config_updated_by])
    |> validate_inclusion(:capture_mode, @valid_capture_modes)
    |> increment_version()
  end

  defp increment_version(changeset) do
    current = get_field(changeset, :config_version) || 1
    put_change(changeset, :config_version, current + 1)
  end
end
