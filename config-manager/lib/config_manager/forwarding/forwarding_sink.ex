defmodule ConfigManager.Forwarding.ForwardingSink do
  @moduledoc "Pool-scoped Vector forwarding sink configuration."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Forwarding.SinkSecret
  alias ConfigManager.SensorPool

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_sink_types ~w(splunk_hec http syslog kafka s3 file)
  @name_format ~r/^[a-zA-Z0-9._-]+$/

  schema "forwarding_sinks" do
    field(:name, :string)
    field(:normalized_name, :string)
    field(:sink_type, :string)
    field(:config, :string)
    field(:enabled, :boolean, default: true)
    field(:last_test_result, :string)
    field(:last_test_at, :utc_datetime_usec)

    belongs_to(:pool, SensorPool)
    has_many(:secrets, SinkSecret, foreign_key: :forwarding_sink_id)

    timestamps(type: :utc_datetime_usec)
  end

  def create_changeset(sink, attrs) do
    sink
    |> cast(attrs, [:pool_id, :name, :sink_type, :config, :enabled])
    |> normalize_name()
    |> validate_required([:pool_id, :name, :sink_type, :config])
    |> validate_name()
    |> validate_inclusion(:sink_type, @valid_sink_types)
    |> put_normalized_name()
    |> validate_config_json()
    |> unique_constraint([:pool_id, :normalized_name],
      name: :forwarding_sinks_pool_id_normalized_name_index,
      message: "a sink with this name already exists in the pool"
    )
    |> foreign_key_constraint(:pool_id)
  end

  def update_changeset(sink, attrs) do
    sink
    |> cast(attrs, [:name, :config, :enabled])
    |> normalize_name()
    |> validate_name()
    |> put_normalized_name()
    |> validate_config_json()
    |> unique_constraint([:pool_id, :normalized_name],
      name: :forwarding_sinks_pool_id_normalized_name_index,
      message: "a sink with this name already exists in the pool"
    )
  end

  def toggle_changeset(sink) do
    change(sink, enabled: !sink.enabled)
  end

  def test_result_changeset(sink, result, tested_at \\ DateTime.utc_now()) do
    case Jason.encode(result) do
      {:ok, encoded} ->
        change(sink,
          last_test_result: encoded,
          last_test_at: DateTime.truncate(tested_at, :microsecond)
        )

      {:error, _reason} ->
        sink
        |> change()
        |> add_error(:last_test_result, "must be JSON encodable")
    end
  end

  def valid_sink_types, do: @valid_sink_types

  defp normalize_name(changeset) do
    update_change(changeset, :name, fn name -> String.trim(to_string(name)) end)
  end

  defp validate_name(changeset) do
    changeset
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:name, @name_format,
      message: "must contain only alphanumeric characters, hyphens, underscores, and periods"
    )
  end

  defp put_normalized_name(changeset) do
    case get_change(changeset, :name) do
      nil -> changeset
      name -> put_change(changeset, :normalized_name, String.downcase(name))
    end
  end

  defp validate_config_json(changeset) do
    case get_change(changeset, :config) do
      nil ->
        changeset

      config ->
        case Jason.decode(config) do
          {:ok, decoded} when is_map(decoded) ->
            changeset

          {:ok, _decoded} ->
            add_error(changeset, :config, "must be a JSON object")

          {:error, _reason} ->
            add_error(changeset, :config, "must be valid JSON")
        end
    end
  end
end
