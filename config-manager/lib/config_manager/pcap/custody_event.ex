defmodule ConfigManager.Pcap.CustodyEvent do
  @moduledoc "Append-only chain-of-custody event for a PCAP carve request."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Pcap.CarveRequest

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @event_types ~w(created downloaded manifest_exported)

  schema "pcap_custody_events" do
    field(:event_type, :string)
    field(:actor_username, :string)
    field(:actor_display_name, :string)
    field(:client_ip, :string)
    field(:detail, :map, default: %{})
    field(:timestamp, :utc_datetime_usec)

    belongs_to(:carve_request, CarveRequest)
  end

  def event_types, do: @event_types

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :carve_request_id,
      :event_type,
      :actor_username,
      :actor_display_name,
      :client_ip,
      :detail,
      :timestamp
    ])
    |> put_default_timestamp()
    |> put_default_detail()
    |> validate_required([:carve_request_id, :event_type, :actor_username, :detail, :timestamp])
    |> validate_inclusion(:event_type, @event_types)
    |> validate_map(:detail)
    |> foreign_key_constraint(:carve_request_id)
  end

  defp put_default_timestamp(changeset) do
    case get_field(changeset, :timestamp) do
      nil -> put_change(changeset, :timestamp, DateTime.utc_now())
      _timestamp -> changeset
    end
  end

  defp put_default_detail(changeset) do
    case get_field(changeset, :detail) do
      nil -> put_change(changeset, :detail, %{})
      _detail -> changeset
    end
  end

  defp validate_map(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_map(value), do: [], else: [{field, "must be a map"}]
    end)
  end
end
