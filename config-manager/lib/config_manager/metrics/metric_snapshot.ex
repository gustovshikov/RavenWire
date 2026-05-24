defmodule ConfigManager.Metrics.MetricSnapshot do
  @moduledoc "Persisted point-in-time sensor health metric sample."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @metric_types ~w(
    packets_received_rate
    drop_percent
    cpu_percent
    memory_bytes
    pcap_disk_used_percent
    clock_offset_ms
    vector_records_per_sec
    sink_buffer_used_percent
  )

  schema "metric_snapshots" do
    field(:metric_type, :string)
    field(:series_key, :string, default: "default")
    field(:value, :float)
    field(:recorded_at, :utc_datetime_usec)
    field(:metadata, :string, default: "{}")

    belongs_to(:sensor_pod, ConfigManager.SensorPod, type: :binary_id)

    timestamps(type: :utc_datetime_usec)
  end

  def valid_metric_types, do: @metric_types

  def changeset(snapshot, attrs) do
    attrs = normalize_metadata_attr(attrs)

    snapshot
    |> cast(attrs, [:sensor_pod_id, :metric_type, :series_key, :value, :recorded_at, :metadata])
    |> put_default_series_key()
    |> validate_required([:sensor_pod_id, :metric_type, :series_key, :value, :recorded_at, :metadata])
    |> validate_inclusion(:metric_type, @metric_types)
    |> validate_format(:series_key, ~r/^\S+$/)
    |> validate_finite_value()
    |> validate_metadata_json()
    |> foreign_key_constraint(:sensor_pod_id)
    |> unique_constraint([:sensor_pod_id, :metric_type, :series_key, :recorded_at],
      name: :metric_snapshots_unique_sample_index
    )
  end

  defp normalize_metadata_attr(attrs) when is_map(attrs) do
    case Map.fetch(attrs, :metadata) do
      {:ok, value} -> Map.put(attrs, :metadata, encode_metadata(value))
      :error -> normalize_string_metadata_attr(attrs)
    end
  end

  defp normalize_metadata_attr(attrs), do: attrs

  defp normalize_string_metadata_attr(attrs) do
    case Map.fetch(attrs, "metadata") do
      {:ok, value} -> Map.put(attrs, "metadata", encode_metadata(value))
      :error -> attrs
    end
  end

  defp encode_metadata(nil), do: "{}"
  defp encode_metadata(value) when is_binary(value), do: value

  defp encode_metadata(value) when is_map(value) do
    case Jason.encode(value) do
      {:ok, encoded} -> encoded
      {:error, _reason} -> value
    end
  end

  defp encode_metadata(value), do: value

  defp put_default_series_key(changeset) do
    case get_field(changeset, :series_key) do
      nil -> put_change(changeset, :series_key, "default")
      "" -> put_change(changeset, :series_key, "default")
      _value -> changeset
    end
  end

  defp validate_finite_value(changeset) do
    validate_change(changeset, :value, fn :value, value ->
      if finite_number?(value), do: [], else: [value: "must be a finite number"]
    end)
  end

  defp finite_number?(value) when is_integer(value), do: true

  defp finite_number?(value) when is_float(value) do
    value == value and value > -1.0e308 and value < 1.0e308
  end

  defp finite_number?(_value), do: false

  defp validate_metadata_json(changeset) do
    validate_change(changeset, :metadata, fn :metadata, value ->
      case Jason.decode(value || "{}") do
        {:ok, decoded} when is_map(decoded) -> []
        {:ok, _decoded} -> [metadata: "must encode a JSON object"]
        {:error, _reason} -> [metadata: "must encode a JSON object"]
      end
    end)
  end
end
