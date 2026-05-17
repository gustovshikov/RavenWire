defmodule ConfigManager.Rules.RulesetRule do
  @moduledoc "Explicit include/exclude SID override for a ruleset."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Rules.Ruleset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_actions ~w(include exclude)

  schema "ruleset_rules" do
    field(:sid, :integer)
    field(:action, :string)

    belongs_to(:ruleset, Ruleset)

    timestamps()
  end

  def changeset(override, attrs) do
    override
    |> cast(attrs, [:ruleset_id, :sid, :action])
    |> validate_required([:ruleset_id, :sid, :action])
    |> validate_number(:sid, greater_than: 0)
    |> validate_inclusion(:action, @valid_actions)
    |> unique_constraint([:ruleset_id, :sid])
    |> foreign_key_constraint(:ruleset_id)
  end
end
