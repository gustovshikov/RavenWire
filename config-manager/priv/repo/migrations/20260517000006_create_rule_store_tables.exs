defmodule ConfigManager.Repo.Migrations.CreateRuleStoreTables do
  use Ecto.Migration

  def up do
    create table(:suricata_rules, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:sid, :integer, null: false)
      add(:message, :text)
      add(:raw_text, :text, null: false)
      add(:category, :string, null: false)
      add(:classtype, :string)
      add(:severity, :integer, null: false, default: 2)
      add(:revision, :integer, null: false, default: 1)
      add(:enabled, :boolean, null: false, default: true)
      add(:repository_id, :binary_id)
      add(:repository_name, :string)

      timestamps()
    end

    create(unique_index(:suricata_rules, [:sid]))
    create(index(:suricata_rules, [:category]))
    create(index(:suricata_rules, [:enabled]))
    create(index(:suricata_rules, [:repository_id]))

    create table(:rule_repositories, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:name, :string, null: false)
      add(:url, :text, null: false)
      add(:repo_type, :string, null: false, default: "custom")
      add(:last_updated_at, :utc_datetime)
      add(:last_update_status, :string, null: false, default: "never_updated")
      add(:last_update_error, :text)
      add(:rule_count, :integer, null: false, default: 0)

      timestamps()
    end

    execute(
      "CREATE UNIQUE INDEX rule_repositories_name_nocase_index ON rule_repositories (name COLLATE NOCASE)"
    )

    create table(:rulesets, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:name, :string, null: false)
      add(:description, :text)
      add(:version, :integer, null: false, default: 1)
      add(:categories, :text, null: false, default: "[]")
      add(:updated_by, :string)

      timestamps()
    end

    execute("CREATE UNIQUE INDEX rulesets_name_nocase_index ON rulesets (name COLLATE NOCASE)")

    create table(:ruleset_rules, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:ruleset_id, references(:rulesets, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:sid, :integer, null: false)
      add(:action, :string, null: false)

      timestamps()
    end

    create(unique_index(:ruleset_rules, [:ruleset_id, :sid]))
    create(index(:ruleset_rules, [:ruleset_id]))

    create table(:pool_ruleset_assignments, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:pool_id, references(:sensor_pools, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:ruleset_id, references(:rulesets, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:assigned_by, :string, null: false)
      add(:deployed_rule_version, :integer)

      timestamps()
    end

    create(unique_index(:pool_ruleset_assignments, [:pool_id]))
    create(index(:pool_ruleset_assignments, [:ruleset_id]))
  end

  def down do
    drop(table(:pool_ruleset_assignments))
    drop(table(:ruleset_rules))
    execute("DROP INDEX IF EXISTS rulesets_name_nocase_index")
    drop(table(:rulesets))
    execute("DROP INDEX IF EXISTS rule_repositories_name_nocase_index")
    drop(table(:rule_repositories))
    drop(table(:suricata_rules))
  end
end
