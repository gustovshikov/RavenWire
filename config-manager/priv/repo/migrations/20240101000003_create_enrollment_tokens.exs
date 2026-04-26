defmodule ConfigManager.Repo.Migrations.CreateEnrollmentTokens do
  use Ecto.Migration

  def change do
    create table(:enrollment_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true
      # The token value itself (UUID, single-use)
      add :token, :string, null: false
      add :created_by, :string
      # Consumed at first use regardless of approval outcome
      add :consumed_at, :utc_datetime
      add :expires_at, :utc_datetime, null: false

      timestamps()
    end

    create unique_index(:enrollment_tokens, [:token])
  end
end
