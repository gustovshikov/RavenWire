defmodule ConfigManager.Bpf.SchemasTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Bpf.{BpfFilterRule, BpfProfile, BpfProfileVersion}

  test "BpfProfile changesets validate modes and version helpers" do
    changeset = BpfProfile.create_changeset(%BpfProfile{}, %{pool_id: Ecto.UUID.generate()})

    assert changeset.valid?
    assert Ecto.Changeset.get_field(changeset, :version) == 1
    assert Ecto.Changeset.get_field(changeset, :composition_mode) == "append"

    invalid =
      BpfProfile.create_changeset(%BpfProfile{}, %{
        pool_id: Ecto.UUID.generate(),
        composition_mode: "merge"
      })

    refute invalid.valid?
    assert %{composition_mode: [_ | _]} = errors_on(invalid)

    profile = %BpfProfile{version: 4, composition_mode: "replace", raw_expression: "tcp"}

    assert Ecto.Changeset.get_change(BpfProfile.increment_version_changeset(profile), :version) ==
             5

    reset = BpfProfile.reset_changeset(profile, "tester")
    assert Ecto.Changeset.get_change(reset, :composition_mode) == "append"
    assert Ecto.Changeset.get_change(reset, :updated_by) == "tester"
  end

  test "BpfFilterRule changeset validates type-specific params" do
    valid =
      BpfFilterRule.changeset(%BpfFilterRule{}, %{
        bpf_profile_id: Ecto.UUID.generate(),
        rule_type: "cidr_pair",
        params: %{"src_cidr" => "10.0.0.0/8", "dst_cidr" => "192.168.1.0/24"},
        label: "east-west",
        position: 1
      })

    assert valid.valid?

    invalid =
      BpfFilterRule.changeset(%BpfFilterRule{}, %{
        bpf_profile_id: Ecto.UUID.generate(),
        rule_type: "port_exclusion",
        params: %{"port" => 70_000},
        position: 1
      })

    refute invalid.valid?
    assert %{params: [_ | _]} = errors_on(invalid)
  end

  test "BpfProfileVersion validates snapshots and positive versions" do
    valid =
      BpfProfileVersion.changeset(%BpfProfileVersion{}, %{
        bpf_profile_id: Ecto.UUID.generate(),
        version: 2,
        raw_expression: "tcp",
        composition_mode: "replace",
        compiled_expression: "tcp",
        rules_snapshot: [%{"rule_type" => "port_exclusion"}],
        created_by: "tester"
      })

    assert valid.valid?

    invalid =
      BpfProfileVersion.changeset(%BpfProfileVersion{}, %{
        bpf_profile_id: Ecto.UUID.generate(),
        version: 0,
        composition_mode: "invalid",
        rules_snapshot: []
      })

    refute invalid.valid?
    assert %{version: [_ | _], composition_mode: [_ | _]} = errors_on(invalid)
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
