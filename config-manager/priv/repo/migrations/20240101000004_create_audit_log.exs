defmodule ConfigManager.Repo.Migrations.CreateAuditLog do
  use Ecto.Migration

  def change do
    create table(:audit_log, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :timestamp, :utc_datetime_usec, null: false
      add :actor, :string, null: false
      add :actor_type, :string, null: false  # user | api_token | system
      add :action, :string, null: false
      add :target_type, :string
      add :target_id, :string
      add :result, :string, null: false  # success | failure
      add :detail, :text  # JSON blob

      # No timestamps() — audit log is append-only; inserted_at is :timestamp
    end

    create index(:audit_log, [:timestamp])
    create index(:audit_log, [:actor])
    create index(:audit_log, [:action])
    create index(:audit_log, [:target_id])
  end
end
