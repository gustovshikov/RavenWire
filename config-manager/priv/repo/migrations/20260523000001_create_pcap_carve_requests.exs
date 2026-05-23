defmodule ConfigManager.Repo.Migrations.CreatePcapCarveRequests do
  use Ecto.Migration

  def change do
    create table(:pcap_carve_requests, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:user_id, references(:users, type: :binary_id, on_delete: :nilify_all))
      add(:actor, :string, null: false)
      add(:actor_type, :string, null: false)

      add(:search_type, :string, null: false)
      add(:search_params, :map, null: false)

      add(:sensor_pod_id, references(:sensor_pods, type: :binary_id, on_delete: :nilify_all))
      add(:sensor_name, :string, null: false)

      add(:status, :string, null: false, default: "pending")
      add(:error_reason, :text)

      add(:file_path, :string)
      add(:file_size_bytes, :integer)
      add(:sha256, :string)
      add(:packet_count, :integer)
      add(:time_span_start, :utc_datetime_usec)
      add(:time_span_end, :utc_datetime_usec)
      add(:expires_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:pcap_carve_requests, [:user_id]))
    create(index(:pcap_carve_requests, [:sensor_pod_id]))
    create(index(:pcap_carve_requests, [:status]))
    create(index(:pcap_carve_requests, [:expires_at]))
    create(index(:pcap_carve_requests, [:inserted_at]))

    create table(:pcap_custody_events, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :carve_request_id,
        references(:pcap_carve_requests, type: :binary_id, on_delete: :delete_all), null: false)

      add(:event_type, :string, null: false)
      add(:actor_username, :string, null: false)
      add(:actor_display_name, :string)
      add(:client_ip, :string)
      add(:detail, :map, null: false, default: %{})
      add(:timestamp, :utc_datetime_usec, null: false)
    end

    create(index(:pcap_custody_events, [:carve_request_id]))
    create(index(:pcap_custody_events, [:timestamp]))
  end
end
