defmodule ConfigManager.Bpf.BpfProfileVersion do
  @moduledoc "Immutable BPF profile version snapshot."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Bpf.{BpfProfile, JsonTerm}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "bpf_profile_versions" do
    field(:version, :integer)
    field(:raw_expression, :string)
    field(:composition_mode, :string)
    field(:compiled_expression, :string)
    field(:rules_snapshot, JsonTerm)
    field(:created_by, :string)

    belongs_to(:bpf_profile, BpfProfile)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(version_record, attrs) do
    version_record
    |> cast(attrs, [
      :bpf_profile_id,
      :version,
      :raw_expression,
      :composition_mode,
      :compiled_expression,
      :rules_snapshot,
      :created_by
    ])
    |> validate_required([:bpf_profile_id, :version, :composition_mode, :rules_snapshot])
    |> validate_number(:version, greater_than: 0)
    |> validate_inclusion(:composition_mode, BpfProfile.valid_composition_modes())
    |> unique_constraint([:bpf_profile_id, :version],
      name: :bpf_profile_versions_bpf_profile_id_version_index,
      message: "version already exists for this profile"
    )
    |> foreign_key_constraint(:bpf_profile_id)
  end
end
