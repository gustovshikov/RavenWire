defmodule ConfigManager.Bpf.MigrationTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Bpf.{BpfFilterRule, BpfProfile, BpfProfileVersion}
  alias ConfigManager.{Repo, SensorPool}

  test "BPF tables cascade delete from sensor pools through profiles" do
    pool = insert_pool!("bpf-migration-pool")
    profile = insert_profile!(pool.id)
    rule = insert_rule!(profile.id)
    version = insert_version!(profile.id)

    Repo.delete!(pool)

    assert Repo.get(BpfProfile, profile.id) == nil
    assert Repo.get(BpfFilterRule, rule.id) == nil
    assert Repo.get(BpfProfileVersion, version.id) == nil
  end

  test "one profile per pool is enforced" do
    pool = insert_pool!("bpf-unique-pool")
    insert_profile!(pool.id)

    assert {:error, changeset} =
             %BpfProfile{}
             |> BpfProfile.create_changeset(%{pool_id: pool.id})
             |> Repo.insert()

    assert %{pool_id: [_ | _]} = errors_on(changeset)
  end

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "tester")
    |> Repo.insert!()
  end

  defp insert_profile!(pool_id) do
    %BpfProfile{}
    |> BpfProfile.create_changeset(%{pool_id: pool_id, updated_by: "tester"})
    |> Repo.insert!()
  end

  defp insert_rule!(profile_id) do
    %BpfFilterRule{}
    |> BpfFilterRule.changeset(%{
      bpf_profile_id: profile_id,
      rule_type: "port_exclusion",
      params: %{"port" => 443, "protocol" => "tcp"},
      position: 0
    })
    |> Repo.insert!()
  end

  defp insert_version!(profile_id) do
    %BpfProfileVersion{}
    |> BpfProfileVersion.changeset(%{
      bpf_profile_id: profile_id,
      version: 1,
      composition_mode: "append",
      rules_snapshot: []
    })
    |> Repo.insert!()
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
