defmodule ConfigManager.Bpf.ContextPropertyTest do
  @moduledoc "Property coverage for BPF context versioning, audits, and persistence."

  use ConfigManager.DataCase, async: false
  use PropCheck

  import Ecto.Query

  alias ConfigManager.Bpf
  alias ConfigManager.Bpf.{BpfFilterRule, BpfProfile, BpfProfileVersion}
  alias ConfigManager.{AuditEntry, Repo, SensorPool}

  property "Property 7: Profile creation initializes correct defaults",
           [:verbose, numtests: 25] do
    forall code <- integer(1, 100_000) do
      pool = insert_pool!("bpf-create-prop-#{code}")
      {:ok, profile} = Bpf.create_profile(pool.id, "property")
      version = Bpf.get_version(profile.id, 1)

      profile.version == 1 and
        profile.raw_expression == nil and
        profile.composition_mode == "append" and
        profile.compiled_expression == nil and
        Bpf.list_rules(profile.id) == [] and
        version.rules_snapshot == []
    end
  end

  property "Property 8: Version increments only on configuration changes",
           [:verbose, numtests: 25] do
    forall code <- integer(1, 100_000) do
      {_pool, profile} = create_profile!(code, "version")
      params = save_params(code)

      {:ok, changed} = Bpf.save_profile(profile, params, "property", compiler: compiler())
      {:ok, unchanged} = Bpf.save_profile(changed, params, "property", compiler: compiler())
      {:ok, _compiled} = Bpf.validate_expression("tcp", compiler: compiler())
      after_validate = Repo.get!(BpfProfile, profile.id)

      changed.version == profile.version + 1 and
        unchanged.version == changed.version and
        after_validate.version == changed.version
    end
  end

  property "Property 9: Every version increment creates an immutable snapshot",
           [:verbose, numtests: 20] do
    forall code <- integer(1, 100_000) do
      {_pool, profile} = create_profile!(code, "snapshot")

      {:ok, version_two_profile} =
        Bpf.save_profile(profile, save_params(code), "property", compiler: compiler())

      version_two_before = Bpf.get_version(profile.id, 2)

      {:ok, version_three_profile} =
        Bpf.save_profile(
          version_two_profile,
          save_params(code + 10_001),
          "property",
          compiler: compiler()
        )

      version_two_after = Bpf.get_version(profile.id, 2)
      version_three = Bpf.get_version(profile.id, 3)

      version_three_profile.version == 3 and
        version_two_before.rules_snapshot == version_two_after.rules_snapshot and
        version_two_before.compiled_expression == version_two_after.compiled_expression and
        version_three.rules_snapshot != version_two_before.rules_snapshot and
        version_three.created_by == "property"
    end
  end

  property "Property 10: Reset clears all state and increments version",
           [:verbose, numtests: 20] do
    forall code <- integer(1, 100_000) do
      {_pool, profile} = create_profile!(code, "reset")

      {:ok, changed} =
        Bpf.save_profile(profile, save_params(code), "property", compiler: compiler())

      {:ok, reset} = Bpf.reset_profile(changed, "property-reset")
      reset_version = Bpf.get_version(profile.id, reset.version)

      reset.version == changed.version + 1 and
        reset.raw_expression == nil and
        reset.composition_mode == "append" and
        reset.compiled_expression == nil and
        Bpf.list_rules(profile.id) == [] and
        reset_version.rules_snapshot == [] and
        reset_version.created_by == "property-reset"
    end
  end

  property "Property 11: Pool deletion cascades to BPF profile, rules, and versions",
           [:verbose, numtests: 20] do
    forall code <- integer(1, 100_000) do
      {pool, profile} = create_profile!(code, "cascade")

      {:ok, _changed} =
        Bpf.save_profile(profile, save_params(code), "property", compiler: compiler())

      Repo.delete!(pool)

      not Repo.exists?(from(p in BpfProfile, where: p.id == ^profile.id)) and
        not Repo.exists?(from(r in BpfFilterRule, where: r.bpf_profile_id == ^profile.id)) and
        not Repo.exists?(from(v in BpfProfileVersion, where: v.bpf_profile_id == ^profile.id))
    end
  end

  property "Property 14: Audit writes are transactional with BPF mutations",
           [:verbose, numtests: 20] do
    forall code <- integer(1, 100_000) do
      case rem(code, 3) do
        0 -> create_rolls_back_on_audit_failure?(code)
        1 -> save_rolls_back_on_audit_failure?(code)
        2 -> reset_rolls_back_on_audit_failure?(code)
      end
    end
  end

  property "Property 13: Every BPF mutation produces a structurally complete audit entry",
           [:verbose, numtests: 20] do
    forall code <- integer(1, 100_000) do
      actor = "audit-property"

      {profile, action} =
        case rem(code, 3) do
          0 ->
            {_pool, profile} = create_profile!(code, "audit-create", actor)
            {profile, "bpf_profile_created"}

          1 ->
            {_pool, profile} = create_profile!(code, "audit-save", actor)

            {:ok, updated} =
              Bpf.save_profile(profile, save_params(code), actor, compiler: compiler())

            {updated, "bpf_profile_updated"}

          2 ->
            {_pool, profile} = create_profile!(code, "audit-reset", actor)

            {:ok, updated} =
              Bpf.save_profile(profile, save_params(code), actor, compiler: compiler())

            {:ok, reset} = Bpf.reset_profile(updated, actor)
            {reset, "bpf_profile_reset"}
        end

      profile.id
      |> audit_entry!(action)
      |> valid_audit_entry?(actor, action, profile.id)
    end
  end

  property "Property 15: Pending deployment detection follows version/deployed-version state",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      {pool, profile} = create_profile!(code, "pending")
      version = rem(code, 20) + 1
      deployed = deployed_version(code, version)

      profile
      |> Ecto.Changeset.change(version: version, last_deployed_version: deployed)
      |> Repo.update!()

      Bpf.bpf_summary(pool.id).pending_deployment == expected_pending?(version, deployed)
    end
  end

  defp create_rolls_back_on_audit_failure?(code) do
    pool = insert_pool!("audit-fail-create-#{code}")
    result = Bpf.create_profile(pool.id, %{username: nil})

    not match?({:ok, _profile}, result) and is_nil(Bpf.get_profile_for_pool(pool.id))
  end

  defp save_rolls_back_on_audit_failure?(code) do
    {_pool, profile} = create_profile!(code, "audit-fail-save")

    result =
      Bpf.save_profile(profile, save_params(code), %{username: nil}, compiler: compiler())

    persisted = Repo.get!(BpfProfile, profile.id)

    not match?({:ok, _profile}, result) and
      persisted.version == 1 and
      Bpf.list_rules(profile.id) == [] and
      is_nil(Bpf.get_version(profile.id, 2))
  end

  defp reset_rolls_back_on_audit_failure?(code) do
    {_pool, profile} = create_profile!(code, "audit-fail-reset")

    {:ok, changed} =
      Bpf.save_profile(profile, save_params(code), "property", compiler: compiler())

    rules_before = Bpf.list_rules(profile.id)

    result = Bpf.reset_profile(changed, %{username: nil})
    persisted = Repo.get!(BpfProfile, profile.id)

    not match?({:ok, _profile}, result) and
      persisted.version == changed.version and
      Bpf.list_rules(profile.id) == rules_before and
      is_nil(Bpf.get_version(profile.id, 3))
  end

  defp valid_audit_entry?(entry, actor, action, target_id) do
    detail =
      case Jason.decode(entry.detail || "") do
        {:ok, decoded} -> decoded
        _error -> :invalid
      end

    not is_nil(entry.id) and
      not is_nil(entry.timestamp) and
      entry.actor == actor and
      entry.actor_type == "user" and
      entry.action == action and
      entry.target_type == "bpf_profile" and
      entry.target_id == target_id and
      entry.result == "success" and
      is_map(detail)
  end

  defp audit_entry!(profile_id, action) do
    Repo.get_by!(AuditEntry, action: action, target_type: "bpf_profile", target_id: profile_id)
  end

  defp create_profile!(code, suffix, actor \\ "property") do
    pool = insert_pool!("bpf-#{suffix}-#{code}")
    {:ok, profile} = Bpf.create_profile(pool.id, actor)
    {pool, profile}
  end

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: unique_name(name)}, "property")
    |> Repo.insert!()
  end

  defp save_params(code) do
    %{
      rules: [
        %{
          rule_type: "port_exclusion",
          params: %{"port" => port(code), "protocol" => protocol(code)},
          label: "port-#{port(code)}",
          enabled: true,
          position: 0
        },
        %{
          rule_type: "cidr_pair",
          params: %{"src_cidr" => "10.0.0.0/8", "dst_cidr" => "192.168.0.0/16"},
          enabled: rem(code, 2) == 0,
          position: 1
        }
      ],
      raw_expression: raw_expression(code),
      composition_mode: "append"
    }
  end

  defp compiler do
    fn expression ->
      {:ok, %{instruction_count: expression |> to_string() |> String.split(" and ") |> length()}}
    end
  end

  defp deployed_version(code, version) do
    case rem(code, 4) do
      0 -> nil
      1 -> version
      2 -> max(version - 1, 0)
      3 -> version + 1
    end
  end

  defp expected_pending?(version, nil), do: version >= 1
  defp expected_pending?(version, deployed), do: version > deployed

  defp port(code), do: rem(code, 65_000) + 1
  defp protocol(code), do: Enum.at(["tcp", "udp", "any"], rem(code, 3))
  defp raw_expression(code), do: Enum.at(["tcp", "udp", nil], rem(code, 3))
  defp unique_name(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"
end
