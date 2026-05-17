defmodule ConfigManager.Rules.Ruleset do
  @moduledoc "Named composition of rule categories and explicit SID overrides."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Rules.{CategoryList, PoolRulesetAssignment, RulesetRule}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @name_format ~r/^[a-zA-Z0-9._-]+$/

  schema "rulesets" do
    field(:name, :string)
    field(:description, :string)
    field(:version, :integer, default: 1)
    field(:categories, CategoryList, default: [])
    field(:updated_by, :string)

    has_many(:overrides, RulesetRule)
    has_many(:pool_assignments, PoolRulesetAssignment)

    timestamps()
  end

  def create_changeset(ruleset, attrs, actor \\ "system") do
    ruleset
    |> cast(attrs, [:name, :description, :categories])
    |> normalize_name()
    |> validate_required([:name])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:name, @name_format,
      message: "must contain only alphanumeric characters, hyphens, underscores, and periods"
    )
    |> validate_categories()
    |> put_change(:version, 1)
    |> put_change(:updated_by, actor)
    |> unique_constraint(:name,
      name: :rulesets_name_nocase_index,
      message: "has already been taken"
    )
    |> unique_constraint(:name,
      name: :rulesets_name_index,
      message: "has already been taken"
    )
  end

  def update_changeset(ruleset, attrs, actor \\ "system") do
    ruleset
    |> cast(attrs, [:name, :description, :categories])
    |> normalize_name()
    |> validate_required([:name])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:name, @name_format,
      message: "must contain only alphanumeric characters, hyphens, underscores, and periods"
    )
    |> validate_categories()
    |> maybe_increment_version(actor)
    |> unique_constraint(:name,
      name: :rulesets_name_nocase_index,
      message: "has already been taken"
    )
    |> unique_constraint(:name,
      name: :rulesets_name_index,
      message: "has already been taken"
    )
  end

  defp normalize_name(changeset) do
    update_change(changeset, :name, fn name -> name |> to_string() |> String.trim() end)
  end

  defp validate_categories(changeset) do
    validate_change(changeset, :categories, fn :categories, categories ->
      if Enum.all?(categories, &valid_category?/1) do
        []
      else
        [categories: "must contain only non-empty category names"]
      end
    end)
  end

  defp valid_category?(category), do: is_binary(category) and String.trim(category) != ""

  defp maybe_increment_version(changeset, actor) do
    if Map.has_key?(changeset.changes, :categories) do
      current = get_field(changeset, :version) || 1

      changeset
      |> put_change(:version, current + 1)
      |> put_change(:updated_by, actor)
    else
      changeset
    end
  end
end
