defmodule ConfigManager.Pcap.CarveRequest do
  @moduledoc "Persistent PCAP carve request lifecycle record."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.{Auth.User, Pcap.CustodyEvent, SensorPod}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(pending dispatched carving completed failed expired)
  @terminal_statuses ~w(completed failed expired)
  @search_types ~w(time_range community_id five_tuple alert_id zeek_uid)
  @actor_types ~w(user api_token system)
  @valid_transitions %{
    "pending" => ~w(dispatched failed),
    "dispatched" => ~w(carving completed failed),
    "carving" => ~w(completed failed),
    "completed" => ~w(expired),
    "failed" => [],
    "expired" => []
  }

  schema "pcap_carve_requests" do
    field(:actor, :string)
    field(:actor_type, :string)
    field(:search_type, :string)
    field(:search_params, :map)
    field(:sensor_name, :string)
    field(:status, :string, default: "pending")
    field(:error_reason, :string)
    field(:file_path, :string)
    field(:file_size_bytes, :integer)
    field(:sha256, :string)
    field(:packet_count, :integer)
    field(:time_span_start, :utc_datetime_usec)
    field(:time_span_end, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)

    belongs_to(:user, User)
    belongs_to(:sensor_pod, SensorPod)
    has_many(:custody_events, CustodyEvent, foreign_key: :carve_request_id)

    timestamps(type: :utc_datetime_usec)
  end

  def statuses, do: @statuses
  def terminal_statuses, do: @terminal_statuses
  def search_types, do: @search_types
  def valid_transitions, do: @valid_transitions

  def terminal?(%__MODULE__{status: status}), do: status in @terminal_statuses

  def create_changeset(request, attrs) do
    request
    |> cast(attrs, [
      :user_id,
      :actor,
      :actor_type,
      :search_type,
      :search_params,
      :sensor_pod_id,
      :sensor_name,
      :status,
      :error_reason,
      :file_path,
      :file_size_bytes,
      :sha256,
      :packet_count,
      :time_span_start,
      :time_span_end,
      :expires_at
    ])
    |> put_default_status()
    |> validate_required([
      :actor,
      :actor_type,
      :search_type,
      :search_params,
      :sensor_pod_id,
      :sensor_name,
      :status
    ])
    |> validate_inclusion(:actor_type, @actor_types)
    |> validate_inclusion(:search_type, @search_types)
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:file_size_bytes, greater_than_or_equal_to: 0)
    |> validate_number(:packet_count, greater_than_or_equal_to: 0)
    |> validate_map(:search_params)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:sensor_pod_id)
  end

  def status_changeset(request, status, attrs \\ %{}) do
    current_status = request.status

    request
    |> cast(Map.put(attrs, :status, status), [
      :status,
      :error_reason,
      :file_path,
      :file_size_bytes,
      :sha256,
      :packet_count,
      :time_span_start,
      :time_span_end,
      :expires_at
    ])
    |> validate_required([:status])
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:file_size_bytes, greater_than_or_equal_to: 0)
    |> validate_number(:packet_count, greater_than_or_equal_to: 0)
    |> validate_transition(current_status)
  end

  defp put_default_status(changeset) do
    case get_field(changeset, :status) do
      nil -> put_change(changeset, :status, "pending")
      _status -> changeset
    end
  end

  defp validate_map(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_map(value), do: [], else: [{field, "must be a map"}]
    end)
  end

  defp validate_transition(changeset, nil), do: changeset

  defp validate_transition(changeset, current_status) do
    next_status = get_field(changeset, :status)

    cond do
      next_status == current_status ->
        changeset

      next_status in Map.get(@valid_transitions, current_status, []) ->
        changeset

      true ->
        add_error(
          changeset,
          :status,
          "invalid transition from #{current_status} to #{next_status}"
        )
    end
  end
end
