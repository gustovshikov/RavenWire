defmodule ConfigManager.Rules.SuricataRule do
  @moduledoc "Database-backed Suricata rule metadata and raw rule text."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "suricata_rules" do
    field(:sid, :integer)
    field(:message, :string)
    field(:raw_text, :string)
    field(:category, :string)
    field(:classtype, :string)
    field(:severity, :integer, default: 2)
    field(:revision, :integer, default: 1)
    field(:enabled, :boolean, default: true)
    field(:repository_id, :binary_id)
    field(:repository_name, :string)

    timestamps()
  end

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :sid,
      :message,
      :raw_text,
      :category,
      :classtype,
      :severity,
      :revision,
      :enabled,
      :repository_id,
      :repository_name
    ])
    |> normalize_string(:category)
    |> normalize_string(:classtype)
    |> validate_required([:sid, :raw_text, :category])
    |> validate_number(:sid, greater_than: 0)
    |> validate_number(:revision, greater_than: 0)
    |> validate_inclusion(:severity, [1, 2, 3])
    |> unique_constraint(:sid)
  end

  def toggle_changeset(rule, enabled) when is_boolean(enabled) do
    change(rule, enabled: enabled)
  end

  defp normalize_string(changeset, field) do
    update_change(changeset, field, fn value -> value |> to_string() |> String.trim() end)
  end
end
