defmodule ConfigManager.Repo.Migrations.CreateBpfProfileVersions do
  use Ecto.Migration

  def change do
    create table(:bpf_profile_versions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:bpf_profile_id, references(:bpf_profiles, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:version, :integer, null: false)
      add(:raw_expression, :text)
      add(:composition_mode, :text, null: false)
      add(:compiled_expression, :text)
      add(:rules_snapshot, :text, null: false)
      add(:created_by, :text)

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:bpf_profile_versions, [:bpf_profile_id, :version]))
  end
end
