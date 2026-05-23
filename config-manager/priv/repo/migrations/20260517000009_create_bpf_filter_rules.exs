defmodule ConfigManager.Repo.Migrations.CreateBpfFilterRules do
  use Ecto.Migration

  def change do
    create table(:bpf_filter_rules, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:bpf_profile_id, references(:bpf_profiles, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:rule_type, :text, null: false)
      add(:params, :text, null: false)
      add(:label, :text)
      add(:enabled, :boolean, null: false, default: true)
      add(:position, :integer, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:bpf_filter_rules, [:bpf_profile_id, :position]))
  end
end
