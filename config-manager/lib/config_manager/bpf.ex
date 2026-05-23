defmodule ConfigManager.Bpf do
  @moduledoc "Pool-scoped BPF profile management context."

  import Ecto.Changeset, only: [put_change: 3]
  import Ecto.Query

  alias ConfigManager.Bpf.{
    BpfFilterRule,
    BpfProfile,
    BpfProfileVersion,
    Compiler,
    ExpressionGenerator
  }

  alias ConfigManager.{Audit, Repo, SensorPod}
  alias Ecto.Multi

  @doc "Gets the BPF profile for a pool, or nil if none exists."
  def get_profile_for_pool(pool_id), do: Repo.get_by(BpfProfile, pool_id: pool_id)

  @doc "Gets a BPF profile by ID, or nil if not found."
  def get_profile(profile_id), do: Repo.get(BpfProfile, profile_id)

  @doc "Creates a new empty BPF profile for a pool."
  def create_profile(pool_id, actor) do
    if get_profile_for_pool(pool_id) do
      {:error, :profile_exists}
    else
      Multi.new()
      |> Multi.insert(
        :profile,
        BpfProfile.create_changeset(%BpfProfile{}, %{
          pool_id: pool_id,
          updated_by: actor_name(actor)
        })
      )
      |> Multi.insert(:version, fn %{profile: profile} ->
        version_changeset(profile, [], actor)
      end)
      |> Audit.append_multi(fn %{profile: profile} ->
        %{
          actor: actor_name(actor),
          actor_type: "user",
          action: "bpf_profile_created",
          target_type: "bpf_profile",
          target_id: profile.id,
          result: "success",
          detail: %{
            pool_id: profile.pool_id,
            version: profile.version,
            composition_mode: profile.composition_mode,
            compiled_expression: profile.compiled_expression,
            rule_count: 0
          }
        }
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{profile: profile}} ->
          broadcast_profile(profile.pool_id, {:bpf_profile_created, profile.pool_id})
          {:ok, profile}

        {:error, :profile, changeset, _changes} ->
          if unique_profile_error?(changeset),
            do: {:error, :profile_exists},
            else: {:error, changeset}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    end
  end

  @doc "Saves the full BPF profile state: rules, raw expression, and composition mode."
  def save_profile(profile, params, actor, opts \\ [])

  def save_profile(%BpfProfile{id: profile_id}, params, actor, opts) do
    current = Repo.get!(BpfProfile, profile_id)
    current_rules = list_rules(current.id)
    raw_expression = normalize_raw(value(params, "raw_expression", current.raw_expression))
    composition_mode = value(params, "composition_mode", current.composition_mode || "append")

    with {:ok, rule_changesets, submitted_rules} <-
           build_rule_changesets(current.id, value(params, "rules", [])),
         :ok <- validate_profile_attrs(current, raw_expression, composition_mode, actor) do
      compiled_expression = generate_expression(submitted_rules, raw_expression, composition_mode)
      compiled_expression_for_storage = blank_to_nil(compiled_expression)
      submitted_snapshot = rules_snapshot(submitted_rules)

      current_state = configuration_state(current, current_rules)

      submitted_state = %{
        raw_expression: raw_expression,
        composition_mode: composition_mode,
        rules: submitted_snapshot
      }

      if current_state == submitted_state do
        {:ok, current}
      else
        case Compiler.compile(compiled_expression, opts) do
          {:ok, _result} ->
            save_changed_profile(
              current,
              current_rules,
              rule_changesets,
              submitted_snapshot,
              %{
                raw_expression: raw_expression,
                composition_mode: composition_mode,
                compiled_expression: compiled_expression_for_storage
              },
              actor
            )

          {:error, %{message: "BPF compilation timed out"}} ->
            {:error, :compilation_timeout}

          {:error, reason} ->
            {:error, {:compilation_failed, reason}}
        end
      end
    end
  end

  @doc "Resets a BPF profile to empty append-mode state."
  def reset_profile(%BpfProfile{id: profile_id}, actor) do
    current = Repo.get!(BpfProfile, profile_id)
    old_version = current.version || 1
    new_version = old_version + 1

    Multi.new()
    |> Multi.delete_all(
      :delete_rules,
      from(r in BpfFilterRule, where: r.bpf_profile_id == ^current.id)
    )
    |> Multi.update(
      :profile,
      current
      |> BpfProfile.reset_changeset(actor)
      |> put_change(:version, new_version)
    )
    |> Multi.insert(:version, fn %{profile: profile} ->
      version_changeset(profile, [], actor)
    end)
    |> Audit.append_multi(fn %{profile: profile} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "bpf_profile_reset",
        target_type: "bpf_profile",
        target_id: profile.id,
        result: "success",
        detail: %{
          pool_id: profile.pool_id,
          old_version: old_version,
          new_version: profile.version,
          compiled_expression: profile.compiled_expression
        }
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{profile: profile}} ->
        broadcast_profile(profile.pool_id, {:bpf_profile_reset, profile.pool_id})
        {:ok, profile}

      {:error, :profile, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Lists all filter rules for a profile, ordered by position."
  def list_rules(profile_id) do
    Repo.all(
      from(r in BpfFilterRule,
        where: r.bpf_profile_id == ^profile_id,
        order_by: [asc: r.position, asc: r.inserted_at]
      )
    )
  end

  @doc "Generates a BPF expression from rules, raw expression, and composition mode."
  def generate_expression(rules, raw_expression, composition_mode) do
    ExpressionGenerator.generate(rules, raw_expression, composition_mode)
  end

  @doc "Validates a BPF expression by compiling it."
  def validate_expression(expression, opts \\ []), do: Compiler.compile(expression, opts)

  @doc "Lists version records for a profile, newest first."
  def list_versions(profile_id, opts \\ []) do
    query =
      from(v in BpfProfileVersion,
        where: v.bpf_profile_id == ^profile_id,
        order_by: [desc: v.version]
      )

    query
    |> maybe_limit(Keyword.get(opts, :limit))
    |> Repo.all()
  end

  @doc "Gets a specific version record for a profile."
  def get_version(profile_id, version_number) do
    Repo.get_by(BpfProfileVersion, bpf_profile_id: profile_id, version: version_number)
  end

  @doc "Returns a pool-level BPF summary for navigation and editor state."
  def bpf_summary(pool_id) do
    case get_profile_for_pool(pool_id) do
      nil ->
        %{
          has_profile: false,
          version: nil,
          last_deployed_version: nil,
          enabled_rule_count: 0,
          total_rule_count: 0,
          has_raw_expression: false,
          composition_mode: nil,
          pending_deployment: false,
          updated_at: nil,
          updated_by: nil
        }

      %BpfProfile{} = profile ->
        counts =
          Repo.one(
            from(r in BpfFilterRule,
              where: r.bpf_profile_id == ^profile.id,
              select: %{
                total: count(r.id),
                enabled: filter(count(r.id), r.enabled == true)
              }
            )
          )

        %{
          has_profile: true,
          version: profile.version,
          last_deployed_version: profile.last_deployed_version,
          enabled_rule_count: counts.enabled || 0,
          total_rule_count: counts.total || 0,
          has_raw_expression: present?(profile.raw_expression),
          composition_mode: profile.composition_mode,
          pending_deployment: pending_deployment?(profile),
          updated_at: profile.updated_at,
          updated_by: profile.updated_by
        }
    end
  end

  @doc "Returns pool sensors whose Health Registry state includes bpf_restart_pending."
  def bpf_restart_pending_sensors(pool_id) do
    sensors =
      SensorPod
      |> where([s], s.pool_id == ^pool_id)
      |> order_by([s], asc: s.name)
      |> Repo.all()
      |> Enum.filter(&bpf_restart_pending?/1)
      |> Enum.map(&%{id: &1.id, name: &1.name})

    %{count: length(sensors), sensors: sensors}
  end

  defp save_changed_profile(
         current,
         current_rules,
         rule_changesets,
         submitted_snapshot,
         attrs,
         actor
       ) do
    old_version = current.version || 1
    new_version = old_version + 1

    Multi.new()
    |> Multi.delete_all(
      :delete_rules,
      from(r in BpfFilterRule, where: r.bpf_profile_id == ^current.id)
    )
    |> Multi.update(
      :profile,
      current
      |> BpfProfile.save_changeset(attrs, actor)
      |> put_change(:version, new_version)
    )
    |> insert_rule_changesets(rule_changesets)
    |> Multi.insert(:version, fn %{profile: profile} ->
      version_changeset(profile, submitted_snapshot, actor)
    end)
    |> Audit.append_multi(fn %{profile: profile} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "bpf_profile_updated",
        target_type: "bpf_profile",
        target_id: profile.id,
        result: "success",
        detail: %{
          pool_id: profile.pool_id,
          old_version: old_version,
          new_version: profile.version,
          compiled_expression: profile.compiled_expression,
          changes: change_summary(current, current_rules, attrs, submitted_snapshot)
        }
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{profile: profile}} ->
        broadcast_profile(profile.pool_id, {:bpf_profile_updated, profile.pool_id})
        {:ok, profile}

      {:error, :profile, changeset, _changes} ->
        {:error, changeset}

      {:error, {_rule, _index}, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  defp insert_rule_changesets(multi, rule_changesets) do
    rule_changesets
    |> Enum.with_index()
    |> Enum.reduce(multi, fn {changeset, index}, multi ->
      Multi.insert(multi, {:rule, index}, changeset)
    end)
  end

  defp build_rule_changesets(profile_id, rules) do
    changesets =
      rules
      |> List.wrap()
      |> Enum.with_index()
      |> Enum.map(fn {rule, index} ->
        attrs =
          rule
          |> normalize_rule_attrs(index)
          |> Map.put(:bpf_profile_id, profile_id)

        BpfFilterRule.changeset(%BpfFilterRule{}, attrs)
      end)

    case Enum.find(changesets, &(not &1.valid?)) do
      nil -> {:ok, changesets, Enum.map(changesets, &Ecto.Changeset.apply_changes/1)}
      changeset -> {:error, changeset}
    end
  end

  defp normalize_rule_attrs(rule, index) when is_map(rule) do
    %{
      rule_type: value(rule, "rule_type", value(rule, "type")),
      params: value(rule, "params", %{}),
      label: normalize_label(value(rule, "label")),
      enabled: to_bool(value(rule, "enabled", true)),
      position: to_int(value(rule, "position", index), index)
    }
  end

  defp normalize_rule_attrs(_rule, index) do
    %{rule_type: nil, params: %{}, label: nil, enabled: true, position: index}
  end

  defp validate_profile_attrs(profile, raw_expression, composition_mode, actor) do
    changeset =
      BpfProfile.save_changeset(
        profile,
        %{
          raw_expression: raw_expression,
          composition_mode: composition_mode,
          compiled_expression: nil
        },
        actor
      )

    if changeset.valid?, do: :ok, else: {:error, changeset}
  end

  defp configuration_state(profile, rules) do
    %{
      raw_expression: normalize_raw(profile.raw_expression),
      composition_mode: profile.composition_mode || "append",
      rules: rules_snapshot(rules)
    }
  end

  defp rules_snapshot(rules) do
    rules
    |> Enum.map(&rule_snapshot/1)
    |> Enum.sort_by(& &1["position"])
  end

  defp rule_snapshot(rule) do
    %{
      "rule_type" => rule.rule_type,
      "params" => normalize_params(rule.params),
      "label" => blank_to_nil(rule.label),
      "enabled" => rule.enabled != false,
      "position" => rule.position || 0
    }
  end

  defp normalize_params(params) when is_map(params) do
    ConfigManager.Bpf.RuleParams.normalize_params(params)
  end

  defp normalize_params(_params), do: %{}

  defp version_changeset(profile, rules_snapshot, actor) do
    BpfProfileVersion.changeset(%BpfProfileVersion{}, %{
      bpf_profile_id: profile.id,
      version: profile.version,
      raw_expression: profile.raw_expression,
      composition_mode: profile.composition_mode || "append",
      compiled_expression: profile.compiled_expression,
      rules_snapshot: rules_snapshot,
      created_by: actor_name(actor)
    })
  end

  defp change_summary(current, current_rules, attrs, submitted_snapshot) do
    current_snapshot = rules_snapshot(current_rules)

    %{
      old_rule_count: length(current_snapshot),
      new_rule_count: length(submitted_snapshot),
      enabled_rule_count: Enum.count(submitted_snapshot, & &1["enabled"]),
      raw_expression_changed?: normalize_raw(current.raw_expression) != attrs.raw_expression,
      composition_mode_changed?: current.composition_mode != attrs.composition_mode,
      rules_changed?: current_snapshot != submitted_snapshot
    }
  end

  defp bpf_restart_pending?(sensor) do
    pending_reason?(sensor.name) or pending_reason?(sensor.id)
  end

  defp pending_reason?(health_key) do
    health_key
    |> ConfigManager.Health.Registry.get_degradation_reasons()
    |> Enum.member?(:bpf_restart_pending)
  end

  defp pending_deployment?(%BpfProfile{version: version, last_deployed_version: nil})
       when is_integer(version),
       do: version >= 1

  defp pending_deployment?(%BpfProfile{version: version, last_deployed_version: deployed})
       when is_integer(version) and is_integer(deployed),
       do: version > deployed

  defp pending_deployment?(_profile), do: false

  defp maybe_limit(query, nil), do: query
  defp maybe_limit(query, limit) when is_integer(limit), do: limit(query, ^limit)
  defp maybe_limit(query, _limit), do: query

  defp value(map, key, default \\ nil)
  defp value(map, key, default) when is_map(map), do: fetch_key(map, key, default)
  defp value(_map, _key, default), do: default

  defp fetch_key(map, key, default) when is_binary(key) do
    atom_key = String.to_atom(key)

    cond do
      Map.has_key?(map, key) -> Map.get(map, key)
      Map.has_key?(map, atom_key) -> Map.get(map, atom_key)
      true -> default
    end
  end

  defp normalize_raw(nil), do: nil

  defp normalize_raw(raw_expression),
    do: raw_expression |> to_string() |> String.trim() |> blank_to_nil()

  defp normalize_label(nil), do: nil
  defp normalize_label(label), do: label |> to_string() |> String.trim() |> blank_to_nil()

  defp blank_to_nil(nil), do: nil
  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  defp present?(value), do: not is_nil(blank_to_nil(to_string(value || "")))

  defp to_bool(value) when value in [true, false], do: value
  defp to_bool(value) when value in ["true", "1", 1], do: true
  defp to_bool(value) when value in ["false", "0", 0], do: false
  defp to_bool(_value), do: true

  defp to_int(value, _default) when is_integer(value), do: value

  defp to_int(value, default) when is_binary(value) do
    case Integer.parse(String.trim(value)) do
      {int, ""} -> int
      _other -> default
    end
  end

  defp to_int(_value, default), do: default

  defp unique_profile_error?(changeset) do
    Enum.any?(changeset.errors, fn
      {:pool_id, {_message, opts}} -> opts[:constraint] == :unique
      _other -> false
    end)
  end

  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor), do: actor
  defp actor_name(_actor), do: "system"

  defp broadcast_profile(pool_id, message),
    do: Phoenix.PubSub.broadcast(ConfigManager.PubSub, "pool:#{pool_id}:bpf", message)
end
