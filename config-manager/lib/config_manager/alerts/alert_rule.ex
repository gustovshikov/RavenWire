defmodule ConfigManager.Alerts.AlertRule do
  @moduledoc "Configurable platform alert rule."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @alert_types ~w(
    sensor_offline
    packet_drops_high
    clock_drift
    disk_critical
    vector_sink_down
    rule_deploy_failed
    cert_expiring
    bpf_validation_failed
    pcap_prune_failed
  )
  @severities ~w(critical warning info)

  schema "alert_rules" do
    field(:alert_type, :string)
    field(:description, :string)
    field(:severity, :string, default: "warning")
    field(:enabled, :boolean, default: true)
    field(:threshold_value, :float)
    field(:threshold_unit, :string)
    field(:builtin, :boolean, default: true)

    timestamps(type: :utc_datetime_usec)
  end

  def alert_types, do: @alert_types
  def severities, do: @severities

  def create_changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :alert_type,
      :description,
      :severity,
      :enabled,
      :threshold_value,
      :threshold_unit,
      :builtin
    ])
    |> validate_required([
      :alert_type,
      :description,
      :severity,
      :enabled,
      :threshold_value,
      :threshold_unit
    ])
    |> validate_inclusion(:alert_type, @alert_types)
    |> validate_inclusion(:severity, @severities)
    |> validate_length(:description, min: 1, max: 1_000)
    |> validate_threshold()
    |> unique_constraint(:alert_type)
  end

  def update_changeset(rule, attrs) do
    rule
    |> cast(attrs, [:severity, :enabled, :threshold_value])
    |> validate_required([:severity, :enabled, :threshold_value])
    |> validate_inclusion(:severity, @severities)
    |> validate_threshold()
  end

  defp validate_threshold(changeset) do
    alert_type = get_field(changeset, :alert_type)
    threshold = get_field(changeset, :threshold_value)

    cond do
      is_nil(threshold) ->
        add_error(changeset, :threshold_value, "is required")

      alert_type in ["packet_drops_high", "disk_critical"] and
          (threshold < 0.0 or threshold > 100.0) ->
        add_error(changeset, :threshold_value, "must be between 0 and 100")

      alert_type in ["sensor_offline", "clock_drift", "cert_expiring"] and threshold <= 0.0 ->
        add_error(changeset, :threshold_value, "must be greater than 0")

      alert_type in [
        "vector_sink_down",
        "rule_deploy_failed",
        "bpf_validation_failed",
        "pcap_prune_failed"
      ] and threshold < 0.0 ->
        add_error(changeset, :threshold_value, "must be 0 or greater")

      true ->
        changeset
    end
  end
end
