defmodule ConfigManager.Bpf.BpfFilterRule do
  @moduledoc "Typed, ordered BPF filter rule in a pool profile."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Bpf.{BpfProfile, JsonTerm, RuleParams}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_rule_types ~w(elephant_flow cidr_pair port_exclusion)

  schema "bpf_filter_rules" do
    field(:rule_type, :string)
    field(:params, JsonTerm)
    field(:label, :string)
    field(:enabled, :boolean, default: true)
    field(:position, :integer)

    belongs_to(:bpf_profile, BpfProfile)

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [:bpf_profile_id, :rule_type, :params, :label, :enabled, :position])
    |> validate_required([:bpf_profile_id, :rule_type, :params, :position])
    |> validate_inclusion(:rule_type, @valid_rule_types)
    |> validate_length(:label, max: 255)
    |> validate_number(:position, greater_than_or_equal_to: 0)
    |> validate_params()
    |> foreign_key_constraint(:bpf_profile_id)
  end

  def valid_rule_types, do: @valid_rule_types

  defp validate_params(changeset) do
    rule_type = get_field(changeset, :rule_type)
    params = get_field(changeset, :params)

    case RuleParams.validate(rule_type, params) do
      :ok -> changeset
      {:error, message} -> add_error(changeset, :params, message)
    end
  end
end
