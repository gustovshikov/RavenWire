defmodule ConfigManager.Rules.PoolRulesetAssignment do
  @moduledoc "One-ruleset assignment for a sensor pool."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Rules.Ruleset
  alias ConfigManager.SensorPool

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "pool_ruleset_assignments" do
    field(:assigned_by, :string)
    field(:deployed_rule_version, :integer)

    belongs_to(:pool, SensorPool)
    belongs_to(:ruleset, Ruleset)

    timestamps()
  end

  def changeset(assignment, attrs) do
    assignment
    |> cast(attrs, [:pool_id, :ruleset_id, :assigned_by, :deployed_rule_version])
    |> validate_required([:pool_id, :ruleset_id, :assigned_by])
    |> validate_number(:deployed_rule_version, greater_than: 0)
    |> unique_constraint(:pool_id,
      name: :pool_ruleset_assignments_pool_id_index,
      message: "has already been assigned"
    )
    |> foreign_key_constraint(:pool_id)
    |> foreign_key_constraint(:ruleset_id)
  end
end
