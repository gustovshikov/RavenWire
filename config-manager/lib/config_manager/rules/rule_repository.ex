defmodule ConfigManager.Rules.RuleRepository do
  @moduledoc "External source repository for Suricata rule archives."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_types ~w(et_open snort_community custom)
  @valid_statuses ~w(never_updated updating success failed)

  schema "rule_repositories" do
    field(:name, :string)
    field(:url, :string)
    field(:repo_type, :string, default: "custom")
    field(:last_updated_at, :utc_datetime)
    field(:last_update_status, :string, default: "never_updated")
    field(:last_update_error, :string)
    field(:rule_count, :integer, default: 0)

    timestamps()
  end

  def changeset(repository, attrs) do
    repository
    |> cast(attrs, [:name, :url, :repo_type])
    |> normalize_name()
    |> validate_required([:name, :url])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:url, ~r/^https?:\/\/\S+$/i, message: "must be a valid HTTP or HTTPS URL")
    |> validate_inclusion(:repo_type, @valid_types)
    |> unique_constraint(:name,
      name: :rule_repositories_name_nocase_index,
      message: "has already been taken"
    )
    |> unique_constraint(:name,
      name: :rule_repositories_name_index,
      message: "has already been taken"
    )
  end

  def update_status_changeset(repository, attrs) do
    repository
    |> cast(attrs, [:last_updated_at, :last_update_status, :last_update_error, :rule_count])
    |> validate_inclusion(:last_update_status, @valid_statuses)
    |> validate_number(:rule_count, greater_than_or_equal_to: 0)
  end

  defp normalize_name(changeset) do
    update_change(changeset, :name, fn name -> name |> to_string() |> String.trim() end)
  end
end
