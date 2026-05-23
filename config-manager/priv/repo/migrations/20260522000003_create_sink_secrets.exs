defmodule ConfigManager.Repo.Migrations.CreateSinkSecrets do
  use Ecto.Migration

  def change do
    create table(:sink_secrets, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :forwarding_sink_id,
        references(:forwarding_sinks, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:secret_name, :text, null: false)
      add(:ciphertext, :text, null: false)
      add(:last_four, :text)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:sink_secrets, [:forwarding_sink_id, :secret_name]))
    create(index(:sink_secrets, [:forwarding_sink_id]))
  end
end
