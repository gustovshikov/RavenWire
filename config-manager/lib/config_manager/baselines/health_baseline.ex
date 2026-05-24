defmodule ConfigManager.Baselines.HealthBaseline do
  @moduledoc "Computed statistical baseline for one sensor or pool metric series."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Metrics.MetricSnapshot
  alias ConfigManager.{SensorPod, SensorPool}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "health_baselines" do
    field(:metric_type, :string)
    field(:series_key, :string, default: "default")
    field(:mean, :float)
    field(:stddev, :float)
    field(:p5, :float)
    field(:p95, :float)
    field(:min_value, :float)
    field(:max_value, :float)
    field(:sample_count, :integer)
    field(:window_start, :utc_datetime_usec)
    field(:window_end, :utc_datetime_usec)
    field(:computed_at, :utc_datetime_usec)

    belongs_to(:sensor_pod, SensorPod, type: :binary_id)
    belongs_to(:pool, SensorPool, type: :binary_id)

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(baseline, attrs) do
    baseline
    |> cast(attrs, [
      :sensor_pod_id,
      :pool_id,
      :metric_type,
      :series_key,
      :mean,
      :stddev,
      :p5,
      :p95,
      :min_value,
      :max_value,
      :sample_count,
      :window_start,
      :window_end,
      :computed_at
    ])
    |> put_default_series_key()
    |> validate_required([
      :metric_type,
      :series_key,
      :mean,
      :stddev,
      :p5,
      :p95,
      :min_value,
      :max_value,
      :sample_count,
      :window_start,
      :window_end,
      :computed_at
    ])
    |> validate_inclusion(:metric_type, MetricSnapshot.valid_metric_types())
    |> validate_format(:series_key, ~r/^\S+$/)
    |> validate_number(:stddev, greater_than_or_equal_to: 0)
    |> validate_number(:sample_count, greater_than: 0)
    |> validate_scope()
    |> foreign_key_constraint(:sensor_pod_id)
    |> foreign_key_constraint(:pool_id)
    |> unique_constraint([:sensor_pod_id, :metric_type, :series_key],
      name: :health_baselines_sensor_unique_index
    )
    |> unique_constraint([:pool_id, :metric_type, :series_key],
      name: :health_baselines_pool_unique_index
    )
  end

  defp put_default_series_key(changeset) do
    case get_field(changeset, :series_key) do
      nil -> put_change(changeset, :series_key, "default")
      "" -> put_change(changeset, :series_key, "default")
      _value -> changeset
    end
  end

  defp validate_scope(changeset) do
    sensor_pod_id = get_field(changeset, :sensor_pod_id)
    pool_id = get_field(changeset, :pool_id)

    case {sensor_pod_id, pool_id} do
      {nil, nil} ->
        add_error(changeset, :sensor_pod_id, "either sensor_pod_id or pool_id must be set")

      {nil, _pool_id} ->
        changeset

      {_sensor_pod_id, nil} ->
        changeset

      {_sensor_pod_id, _pool_id} ->
        add_error(changeset, :pool_id, "cannot set both sensor_pod_id and pool_id")
    end
  end
end
