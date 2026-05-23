defmodule ConfigManager.Bpf.BpfProfile do
  @moduledoc "Pool-scoped BPF filter profile metadata."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Bpf.{BpfFilterRule, BpfProfileVersion}
  alias ConfigManager.SensorPool

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_composition_modes ~w(append replace)

  schema "bpf_profiles" do
    field(:version, :integer, default: 1)
    field(:last_deployed_version, :integer)
    field(:raw_expression, :string)
    field(:composition_mode, :string, default: "append")
    field(:compiled_expression, :string)
    field(:updated_by, :string)

    belongs_to(:pool, SensorPool)
    has_many(:rules, BpfFilterRule, foreign_key: :bpf_profile_id)
    has_many(:versions, BpfProfileVersion, foreign_key: :bpf_profile_id)

    timestamps(type: :utc_datetime_usec)
  end

  def create_changeset(profile, attrs) do
    profile
    |> cast(attrs, [:pool_id, :composition_mode, :updated_by])
    |> validate_required([:pool_id])
    |> validate_inclusion(:composition_mode, @valid_composition_modes)
    |> put_change(:version, 1)
    |> put_change(:raw_expression, nil)
    |> put_change(:compiled_expression, nil)
    |> unique_constraint(:pool_id,
      name: :bpf_profiles_pool_id_index,
      message: "a BPF profile already exists for this pool"
    )
    |> foreign_key_constraint(:pool_id)
  end

  def save_changeset(profile, attrs, actor) do
    profile
    |> cast(attrs, [:raw_expression, :composition_mode, :compiled_expression])
    |> validate_inclusion(:composition_mode, @valid_composition_modes)
    |> put_change(:updated_by, actor_name(actor))
  end

  def increment_version_changeset(profile) do
    change(profile, version: (profile.version || 1) + 1)
  end

  def reset_changeset(profile, actor) do
    change(profile,
      raw_expression: nil,
      composition_mode: "append",
      compiled_expression: nil,
      updated_by: actor_name(actor)
    )
  end

  def deploy_changeset(profile, version_number) do
    profile
    |> change(last_deployed_version: version_number)
    |> validate_number(:last_deployed_version, greater_than: 0)
  end

  def valid_composition_modes, do: @valid_composition_modes

  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor), do: actor
  defp actor_name(_actor), do: "system"
end
