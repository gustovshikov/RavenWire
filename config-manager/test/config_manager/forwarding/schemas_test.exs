defmodule ConfigManager.Forwarding.SchemasTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Forwarding.{ForwardingSink, SinkSecret}
  alias ConfigManager.SensorPool

  test "ForwardingSink changeset normalizes names and validates sink type and JSON config" do
    changeset =
      ForwardingSink.create_changeset(%ForwardingSink{}, %{
        pool_id: Ecto.UUID.generate(),
        name: "  Splunk_HEC.1  ",
        sink_type: "splunk_hec",
        config: ~s({"endpoint":"https://splunk.example"})
      })

    assert changeset.valid?
    assert Ecto.Changeset.get_change(changeset, :name) == "Splunk_HEC.1"
    assert Ecto.Changeset.get_change(changeset, :normalized_name) == "splunk_hec.1"

    invalid_type =
      ForwardingSink.create_changeset(%ForwardingSink{}, %{
        pool_id: Ecto.UUID.generate(),
        name: "bad-type",
        sink_type: "smtp",
        config: "{}"
      })

    refute invalid_type.valid?
    assert %{sink_type: [_ | _]} = errors_on(invalid_type)

    invalid_json =
      ForwardingSink.create_changeset(%ForwardingSink{}, %{
        pool_id: Ecto.UUID.generate(),
        name: "bad-json",
        sink_type: "file",
        config: "not json"
      })

    refute invalid_json.valid?
    assert %{config: [_ | _]} = errors_on(invalid_json)
  end

  test "SinkSecret changeset enforces required encrypted fields" do
    valid =
      SinkSecret.changeset(%SinkSecret{}, %{
        forwarding_sink_id: Ecto.UUID.generate(),
        secret_name: "hec_token",
        ciphertext: Base.encode64("encrypted"),
        last_four: "1234"
      })

    assert valid.valid?

    invalid =
      SinkSecret.changeset(%SinkSecret{}, %{
        forwarding_sink_id: Ecto.UUID.generate(),
        secret_name: "bad secret",
        ciphertext: ""
      })

    refute invalid.valid?
    assert %{secret_name: [_ | _]} = errors_on(invalid)
  end

  test "SensorPool schema mode changeset validates allowed modes and versions changes only on mode changes" do
    pool = %SensorPool{schema_mode: "raw", forwarding_config_version: 0}

    changed = SensorPool.schema_mode_changeset(pool, %{schema_mode: "ecs"}, "tester")

    assert changed.valid?
    assert Ecto.Changeset.get_change(changed, :schema_mode) == "ecs"
    assert Ecto.Changeset.get_change(changed, :forwarding_config_version) == 1
    assert Ecto.Changeset.get_change(changed, :forwarding_config_updated_by) == "tester"

    unchanged = SensorPool.schema_mode_changeset(pool, %{schema_mode: "raw"}, "tester")
    assert unchanged.valid?
    refute Map.has_key?(unchanged.changes, :forwarding_config_version)

    invalid = SensorPool.schema_mode_changeset(pool, %{schema_mode: "cim"}, "tester")
    refute invalid.valid?
    assert %{schema_mode: [_ | _]} = errors_on(invalid)
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
