defmodule ConfigManager.Alerts.Alert do
  @moduledoc "Persisted platform alert instance."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.SensorPod
  alias ConfigManager.Alerts.AlertRule

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(firing acknowledged resolved)

  schema "alerts" do
    field(:alert_type, :string)
    field(:sensor_pod_id, :string)
    field(:severity, :string)
    field(:status, :string, default: "firing")
    field(:message, :string)
    field(:threshold_value, :float)
    field(:observed_value, :float)
    field(:fired_at, :utc_datetime_usec)
    field(:acknowledged_at, :utc_datetime_usec)
    field(:acknowledged_by, :string)
    field(:resolved_at, :utc_datetime_usec)
    field(:resolved_by, :string)
    field(:note, :string)

    belongs_to(:sensor_pod, SensorPod, foreign_key: :sensor_pod_db_id)

    timestamps(type: :utc_datetime_usec)
  end

  def statuses, do: @statuses

  def fire_changeset(alert, attrs) do
    alert
    |> cast(attrs, [
      :alert_type,
      :sensor_pod_id,
      :sensor_pod_db_id,
      :severity,
      :status,
      :message,
      :threshold_value,
      :observed_value,
      :fired_at
    ])
    |> put_default_status()
    |> put_default_fired_at()
    |> validate_required([:alert_type, :sensor_pod_id, :severity, :status, :message, :fired_at])
    |> validate_inclusion(:alert_type, AlertRule.alert_types())
    |> validate_inclusion(:severity, AlertRule.severities())
    |> validate_inclusion(:status, ["firing"])
    |> validate_length(:message, min: 1, max: 2_000)
    |> foreign_key_constraint(:sensor_pod_db_id)
  end

  def acknowledge_changeset(alert, actor, opts \\ []) do
    alert
    |> change(%{
      status: "acknowledged",
      acknowledged_at: DateTime.utc_now() |> DateTime.truncate(:microsecond),
      acknowledged_by: actor_name(actor),
      note: normalize_note(Keyword.get(opts, :note))
    })
    |> validate_transition("acknowledged")
  end

  def resolve_changeset(alert, actor, opts \\ []) do
    alert
    |> change(%{
      status: "resolved",
      resolved_at: DateTime.utc_now() |> DateTime.truncate(:microsecond),
      resolved_by: actor_name(actor),
      note: normalize_note(Keyword.get(opts, :note, alert.note))
    })
    |> validate_transition("resolved")
  end

  defp put_default_status(changeset) do
    case get_field(changeset, :status) do
      nil -> put_change(changeset, :status, "firing")
      _status -> changeset
    end
  end

  defp put_default_fired_at(changeset) do
    case get_field(changeset, :fired_at) do
      nil ->
        put_change(changeset, :fired_at, DateTime.utc_now() |> DateTime.truncate(:microsecond))

      _fired_at ->
        changeset
    end
  end

  defp validate_transition(%{data: %{status: "firing"}} = changeset, status)
       when status in ["acknowledged", "resolved"],
       do: changeset

  defp validate_transition(%{data: %{status: "acknowledged"}} = changeset, "resolved"),
    do: changeset

  defp validate_transition(changeset, status) do
    add_error(changeset, :status, "cannot transition from #{changeset.data.status} to #{status}")
  end

  defp actor_name(%{username: username}) when is_binary(username) and username != "", do: username
  defp actor_name(actor) when is_binary(actor) and actor != "", do: actor
  defp actor_name(_actor), do: "system"

  defp normalize_note(nil), do: nil

  defp normalize_note(note) do
    value = note |> to_string() |> String.trim()

    case value do
      "" -> nil
      value -> String.slice(value, 0, 2_000)
    end
  end
end
