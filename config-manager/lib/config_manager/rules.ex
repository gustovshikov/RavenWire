defmodule ConfigManager.Rules do
  @moduledoc "Rule Store management context for rules, categories, repositories, rulesets, and deployment."

  import Ecto.Query

  alias ConfigManager.Rules.{
    Compiler,
    Fetcher,
    PoolRulesetAssignment,
    RuleRepository,
    Ruleset,
    RulesetRule,
    SuricataRule
  }

  alias ConfigManager.{Audit, AuditEntry, Repo, RuleDeployer, SensorPod, SensorPool}
  alias Ecto.Multi

  @sort_fields %{
    "sid" => :sid,
    "message" => :message,
    "category" => :category,
    "revision" => :revision,
    "severity" => :severity,
    "enabled" => :enabled,
    sid: :sid,
    message: :message,
    category: :category,
    revision: :revision,
    severity: :severity,
    enabled: :enabled
  }
  @deployment_actions ~w(rules_deployed adhoc_rules_deployed)

  @doc "Lists rules with search, filtering, sorting, and pagination."
  def list_rules(opts \\ []) do
    page = max(to_int(opt(opts, :page, 1)), 1)
    page_size = max(to_int(opt(opts, :page_size, 25)), 1)

    query =
      SuricataRule
      |> maybe_search(opt(opts, :search))
      |> maybe_filter(:category, opt(opts, :category))
      |> maybe_filter(:repository_id, opt(opts, :repository_id) || opt(opts, :repo_id))
      |> maybe_filter_repository(opt(opts, :repository) || opt(opts, :repo))

    total_count = Repo.aggregate(query, :count, :id)

    entries =
      query
      |> apply_sort(opt(opts, :sort_by, :sid), opt(opts, :sort_dir, :asc))
      |> limit(^page_size)
      |> offset(^((page - 1) * page_size))
      |> Repo.all()

    %{
      entries: entries,
      page: page,
      page_size: page_size,
      total_count: total_count,
      total_pages: total_pages(total_count, page_size)
    }
  end

  @doc "Gets a single rule by ID."
  def get_rule(id), do: Repo.get(SuricataRule, id)

  @doc "Gets a single rule by SID."
  def get_rule_by_sid(sid), do: Repo.get_by(SuricataRule, sid: to_int(sid))

  @doc "Toggles a rule's enabled status and records an audit entry."
  def toggle_rule(%SuricataRule{} = rule, actor) do
    previous_state = rule.enabled
    new_state = !previous_state

    Multi.new()
    |> Multi.update(:rule, SuricataRule.toggle_changeset(rule, new_state))
    |> Audit.append_multi(fn %{rule: updated} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "rule_toggled",
        target_type: "suricata_rule",
        target_id: updated.id,
        result: "success",
        detail: %{sid: updated.sid, previous_state: previous_state, new_state: updated.enabled}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{rule: updated}} ->
        broadcast_rules({:rule_toggled, updated.id})
        {:ok, updated}

      {:error, :rule, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Bulk toggles enabled status for a list of rule IDs and records a summary audit entry."
  def bulk_toggle_rules(rule_ids, enabled, actor) when is_boolean(enabled) do
    ids = rule_ids |> List.wrap() |> Enum.reject(&is_nil/1) |> Enum.uniq()

    Multi.new()
    |> Multi.run(:rules, fn repo, _changes ->
      rules =
        repo.all(
          from(r in SuricataRule,
            where: r.id in ^ids,
            order_by: [asc: r.sid]
          )
        )

      {:ok, rules}
    end)
    |> Multi.update_all(
      :updated_rules,
      fn _changes -> from(r in SuricataRule, where: r.id in ^ids) end,
      set: [enabled: enabled]
    )
    |> Audit.append_multi(fn %{rules: rules, updated_rules: {count, _rows}} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "bulk_rules_toggled",
        target_type: "rule_store",
        target_id: "bulk",
        result: "success",
        detail: %{count: count, new_state: enabled, sids: Enum.map(rules, & &1.sid)}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{updated_rules: {count, _rows}}} ->
        broadcast_rules({:rules_bulk_toggled, ids, enabled})
        {:ok, count}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Lists all categories with total, enabled, and disabled counts."
  def list_categories do
    Repo.all(
      from(r in SuricataRule,
        group_by: r.category,
        order_by: [asc: r.category],
        select: %{
          name: r.category,
          total: count(r.id),
          enabled: fragment("sum(case when ? = 1 then 1 else 0 end)", r.enabled),
          disabled: fragment("sum(case when ? = 0 then 1 else 0 end)", r.enabled)
        }
      )
    )
  end

  @doc "Toggles all rules in a category and records an audit entry."
  def toggle_category(category_name, enabled, actor) when is_boolean(enabled) do
    category = category_name |> to_string() |> String.trim()

    Multi.new()
    |> Multi.run(:rules, fn repo, _changes ->
      rules =
        repo.all(
          from(r in SuricataRule,
            where: r.category == ^category,
            order_by: [asc: r.sid]
          )
        )

      {:ok, rules}
    end)
    |> Multi.update_all(
      :updated_rules,
      fn _changes -> from(r in SuricataRule, where: r.category == ^category) end,
      set: [enabled: enabled]
    )
    |> Audit.append_multi(fn %{updated_rules: {count, _rows}} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "category_toggled",
        target_type: "rule_category",
        target_id: category,
        result: "success",
        detail: %{category: category, affected_count: count, new_state: enabled}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{updated_rules: {count, _rows}}} ->
        broadcast_rules({:category_toggled, category})
        {:ok, count}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Lists configured rule repositories."
  def list_repositories do
    Repo.all(from(r in RuleRepository, order_by: [asc: r.name]))
  end

  @doc "Gets a configured rule repository by ID."
  def get_repository(id), do: Repo.get(RuleRepository, id)

  @doc "Creates a rule repository and writes an audit entry."
  def create_repository(attrs, actor) do
    Multi.new()
    |> Multi.insert(:repository, RuleRepository.changeset(%RuleRepository{}, attrs))
    |> Audit.append_multi(fn %{repository: repository} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "repository_added",
        target_type: "rule_repository",
        target_id: repository.id,
        result: "success",
        detail: %{
          name: repository.name,
          url: repository.url,
          repo_type: repository.repo_type
        }
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{repository: repository}} ->
        broadcast_repositories({:repository_created, repository})
        {:ok, repository}

      {:error, :repository, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Deletes a repository record while preserving imported rules."
  def delete_repository(%RuleRepository{} = repository, actor) do
    preserved_rule_count = repository_rule_count(repository.id)

    Multi.new()
    |> Multi.delete(:repository, repository)
    |> Audit.append_multi(fn _changes ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "repository_deleted",
        target_type: "rule_repository",
        target_id: repository.id,
        result: "success",
        detail: %{name: repository.name, preserved_rule_count: preserved_rule_count}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{repository: deleted}} ->
        broadcast_repositories({:repository_deleted, deleted.id})
        {:ok, deleted}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Marks a repository updating and starts an async fetch/parse/upsert task."
  def update_repository(%RuleRepository{} = repository, actor, opts \\ []) do
    start_task? = Keyword.get(opts, :start_task?, true)
    fetcher = Keyword.get(opts, :fetcher, Fetcher)

    repository
    |> RuleRepository.update_status_changeset(%{
      last_update_status: "updating",
      last_update_error: nil
    })
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        broadcast_repositories({:repository_updating, updated.id})

        if start_task? do
          Task.Supervisor.start_child(ConfigManager.Rules.TaskSupervisor, fn ->
            run_repository_update(updated.id, actor, fetcher)
          end)
        end

        {:ok, :updating}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc "Bulk upserts parsed rules by SID for a repository."
  def bulk_upsert_rules(rules_data, %RuleRepository{} = repository, actor)
      when is_list(rules_data) do
    bulk_upsert_rules(rules_data, repository.id, actor)
  end

  def bulk_upsert_rules(rules_data, repository_id, actor) when is_list(rules_data) do
    with %RuleRepository{} = repository <- Repo.get(RuleRepository, repository_id) do
      Multi.new()
      |> Multi.run(:upsert_counts, fn repo, _changes ->
        rules_data
        |> dedupe_rules_data()
        |> Enum.reduce_while({:ok, %{added: 0, updated: 0, unchanged: 0}}, fn rule_data,
                                                                              {:ok, counts} ->
          case upsert_rule(repo, rule_data, repository) do
            {:ok, action} ->
              {:cont, {:ok, Map.update!(counts, action, &(&1 + 1))}}

            {:error, reason} ->
              {:halt, {:error, reason}}
          end
        end)
      end)
      |> Audit.append_multi(fn %{upsert_counts: counts} ->
        %{
          actor: actor_name(actor),
          actor_type: "user",
          action: "repository_updated",
          target_type: "rule_repository",
          target_id: repository.id,
          result: "success",
          detail:
            Map.merge(counts, %{
              name: repository.name,
              repository_id: repository.id
            })
        }
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{upsert_counts: counts}} ->
          broadcast_rules({:rules_updated, repository.id})
          {:ok, counts}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    else
      nil -> {:error, :repository_not_found}
    end
  end

  def bulk_upsert_rules(_rules_data, _repository_id, _actor), do: {:error, :invalid_rules}

  @doc "Lists all rulesets with effective rule counts and assigned pool counts."
  def list_rulesets do
    pool_counts =
      Repo.all(
        from(a in PoolRulesetAssignment,
          group_by: a.ruleset_id,
          select: {a.ruleset_id, count(a.id)}
        )
      )
      |> Map.new()

    Ruleset
    |> order_by([r], asc: r.name)
    |> preload([:overrides, :pool_assignments])
    |> Repo.all()
    |> Enum.map(fn ruleset ->
      %{
        ruleset: ruleset,
        effective_count: effective_rule_count(ruleset),
        pool_count: Map.get(pool_counts, ruleset.id, 0)
      }
    end)
  end

  @doc "Gets a ruleset by ID with overrides and pool assignments preloaded."
  def get_ruleset(id) do
    Ruleset
    |> preload([:overrides, :pool_assignments])
    |> Repo.get(id)
  end

  @doc "Gets a ruleset by ID with overrides and pool assignments preloaded, raising on miss."
  def get_ruleset!(id) do
    Ruleset
    |> preload([:overrides, :pool_assignments])
    |> Repo.get!(id)
  end

  @doc "Creates a ruleset and writes an audit entry."
  def create_ruleset(attrs, actor) do
    Multi.new()
    |> Multi.insert(:ruleset, Ruleset.create_changeset(%Ruleset{}, attrs, actor_name(actor)))
    |> Audit.append_multi(fn %{ruleset: ruleset} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "ruleset_created",
        target_type: "ruleset",
        target_id: ruleset.id,
        result: "success",
        detail: %{name: ruleset.name, categories: ruleset.categories, override_count: 0}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{ruleset: ruleset}} ->
        broadcast_rulesets({:ruleset_created, ruleset})
        {:ok, ruleset}

      {:error, :ruleset, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Updates ruleset metadata or category composition and writes an audit entry."
  def update_ruleset(%Ruleset{} = ruleset, attrs, actor) do
    ruleset = Repo.reload!(ruleset)
    changeset = Ruleset.update_changeset(ruleset, attrs, actor_name(actor))
    changed_fields = changeset.changes |> Map.keys() |> Enum.map(&to_string/1)

    Multi.new()
    |> Multi.update(:ruleset, changeset)
    |> Audit.append_multi(fn %{ruleset: updated} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "ruleset_updated",
        target_type: "ruleset",
        target_id: updated.id,
        result: "success",
        detail: %{name: updated.name, changes: changed_fields, version: updated.version}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{ruleset: updated}} ->
        updated = Repo.preload(updated, [:overrides, :pool_assignments])
        broadcast_rulesets({:ruleset_updated, updated})
        {:ok, updated}

      {:error, :ruleset, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Deletes a ruleset and its dependent assignments and overrides."
  def delete_ruleset(%Ruleset{} = ruleset, actor) do
    ruleset = Repo.reload!(ruleset)
    affected_pool_count = assignment_count(ruleset.id)

    Multi.new()
    |> Multi.delete(:ruleset, ruleset)
    |> Audit.append_multi(fn _changes ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "ruleset_deleted",
        target_type: "ruleset",
        target_id: ruleset.id,
        result: "success",
        detail: %{name: ruleset.name, affected_pool_count: affected_pool_count}
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{ruleset: deleted}} ->
        broadcast_rulesets({:ruleset_deleted, deleted.id})
        {:ok, deleted}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Adds or updates an explicit SID override on a ruleset."
  def add_ruleset_override(%Ruleset{} = ruleset, sid, action, actor) do
    sid = to_int(sid)
    action = action |> to_string() |> String.trim()

    cond do
      action == "include" and is_nil(get_rule_by_sid(sid)) ->
        {:error, :rule_not_found}

      true ->
        upsert_ruleset_override(Repo.reload!(ruleset), sid, action, actor)
    end
  end

  @doc "Removes an explicit SID override from a ruleset."
  def remove_ruleset_override(%Ruleset{} = ruleset, sid, actor) do
    ruleset = Repo.reload!(ruleset)
    sid = to_int(sid)

    case Repo.get_by(RulesetRule, ruleset_id: ruleset.id, sid: sid) do
      nil ->
        {:error, :override_not_found}

      override ->
        Multi.new()
        |> Multi.delete(:override, override)
        |> Multi.update(:ruleset, ruleset_version_changeset(ruleset, actor))
        |> Audit.append_multi(fn %{ruleset: updated} ->
          %{
            actor: actor_name(actor),
            actor_type: "user",
            action: "ruleset_updated",
            target_type: "ruleset",
            target_id: updated.id,
            result: "success",
            detail: %{
              name: updated.name,
              changes: ["override_removed"],
              sid: override.sid,
              action: override.action,
              version: updated.version
            }
          }
        end)
        |> Repo.transaction()
        |> case do
          {:ok, %{override: deleted, ruleset: updated}} ->
            broadcast_rulesets({:ruleset_updated, Repo.preload(updated, :overrides)})
            {:ok, deleted}

          {:error, :ruleset, changeset, _changes} ->
            {:error, changeset}

          {:error, _step, reason, _changes} ->
            {:error, reason}
        end
    end
  end

  @doc "Computes the enabled effective rule set for a ruleset."
  def effective_rules(%Ruleset{} = ruleset) do
    ruleset = Repo.preload(ruleset, :overrides)
    categories = ruleset.categories || []

    include_sids =
      ruleset.overrides
      |> Enum.filter(&(&1.action == "include"))
      |> Enum.map(& &1.sid)

    exclude_sids =
      ruleset.overrides
      |> Enum.filter(&(&1.action == "exclude"))
      |> Enum.map(& &1.sid)

    Repo.all(
      from(r in SuricataRule,
        where: r.enabled == true,
        where: r.category in ^categories or r.sid in ^include_sids,
        where: r.sid not in ^exclude_sids,
        order_by: [asc: r.sid]
      )
    )
  end

  def effective_rules(ruleset_id) do
    case get_ruleset(ruleset_id) do
      nil -> []
      ruleset -> effective_rules(ruleset)
    end
  end

  @doc "Returns the enabled effective rule count for a ruleset."
  def effective_rule_count(ruleset_or_id), do: ruleset_or_id |> effective_rules() |> length()

  @doc "Assigns a ruleset to a pool, replacing any existing pool assignment."
  def assign_ruleset_to_pool(%Ruleset{} = ruleset, %SensorPool{} = pool, actor) do
    ruleset = Repo.reload!(ruleset)
    pool = Repo.reload!(pool)
    existing = Repo.get_by(PoolRulesetAssignment, pool_id: pool.id)

    assignment_changeset =
      (existing || %PoolRulesetAssignment{})
      |> PoolRulesetAssignment.changeset(%{
        pool_id: pool.id,
        ruleset_id: ruleset.id,
        assigned_by: actor_name(actor),
        deployed_rule_version: nil
      })

    operation = if existing, do: &Multi.update/3, else: &Multi.insert/3

    Multi.new()
    |> operation.(:assignment, assignment_changeset)
    |> Audit.append_multi(fn %{assignment: assignment} ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "ruleset_assigned_to_pool",
        target_type: "pool",
        target_id: pool.id,
        result: "success",
        detail: %{
          pool_name: pool.name,
          ruleset_name: ruleset.name,
          ruleset_id: ruleset.id,
          previous_ruleset_id: existing && existing.ruleset_id,
          assignment_id: assignment.id
        }
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{assignment: assignment}} ->
        assignment = Repo.preload(assignment, [:pool, :ruleset])
        broadcast_rulesets({:ruleset_assigned, pool.id, ruleset.id})
        {:ok, assignment}

      {:error, :assignment, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc "Removes the current ruleset assignment from a pool."
  def unassign_ruleset_from_pool(%SensorPool{} = pool, actor) do
    pool = Repo.reload!(pool)

    case pool_assignment(pool.id) do
      nil ->
        {:error, :no_assignment}

      assignment ->
        previous_ruleset_name = assignment.ruleset && assignment.ruleset.name

        Multi.new()
        |> Multi.delete(:assignment, assignment)
        |> Audit.append_multi(fn _changes ->
          %{
            actor: actor_name(actor),
            actor_type: "user",
            action: "ruleset_unassigned_from_pool",
            target_type: "pool",
            target_id: pool.id,
            result: "success",
            detail: %{
              pool_name: pool.name,
              previous_ruleset_name: previous_ruleset_name,
              previous_ruleset_id: assignment.ruleset_id
            }
          }
        end)
        |> Repo.transaction()
        |> case do
          {:ok, %{assignment: deleted}} ->
            broadcast_rulesets({:ruleset_unassigned, pool.id})
            {:ok, deleted}

          {:error, _step, reason, _changes} ->
            {:error, reason}
        end
    end
  end

  @doc "Gets the current ruleset assignment for a pool."
  def pool_assignment(pool_id) do
    PoolRulesetAssignment
    |> preload([:pool, :ruleset])
    |> Repo.get_by(pool_id: pool_id)
  end

  @doc "Gets the currently assigned ruleset for a pool."
  def pool_ruleset(pool_id) do
    case pool_assignment(pool_id) do
      %PoolRulesetAssignment{ruleset: ruleset} -> Repo.preload(ruleset, :overrides)
      nil -> nil
    end
  end

  @doc "Deploys the assigned ruleset to a pool's enrolled sensors."
  def deploy_ruleset_to_pool(pool_id, actor, opts \\ []) do
    compiler = Keyword.get(opts, :compiler, Compiler)
    deployer = Keyword.get(opts, :deployer, RuleDeployer)

    with %PoolRulesetAssignment{} = assignment <- pool_assignment(pool_id),
         %Ruleset{} = ruleset <- assignment.ruleset,
         {:ok, rule_files} <- compiler.compile(ruleset.id),
         {:ok, results} <- deploy_rules(deployer, pool_id, rule_files, ruleset, actor, opts),
         {:ok, _changes} <- record_rule_deployment(assignment, ruleset, pool_id, actor, results) do
      broadcast_rulesets({:rules_deployed, pool_id, ruleset.version})
      {:ok, %{results: results, version: ruleset.version}}
    else
      nil -> {:error, :no_assignment}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Returns the deployed rule version recorded on a pool assignment."
  def deployed_rule_version(pool_id) do
    case pool_assignment(pool_id) do
      %PoolRulesetAssignment{deployed_rule_version: version} -> version
      nil -> nil
    end
  end

  @doc "Lists rule deployment audit entries."
  def list_rule_deployments(opts \\ []) do
    page = max(to_int(opt(opts, :page, 1)), 1)
    page_size = max(to_int(opt(opts, :page_size, 25)), 1)

    query =
      AuditEntry
      |> where([a], a.action in ^@deployment_actions)
      |> maybe_filter_pool_deployment(opt(opts, :pool_id))
      |> order_by([a], desc: a.timestamp)

    total_count = Repo.aggregate(query, :count, :id)

    %{
      entries:
        query
        |> limit(^page_size)
        |> offset(^((page - 1) * page_size))
        |> Repo.all(),
      page: page,
      page_size: page_size,
      total_count: total_count,
      total_pages: total_pages(total_count, page_size)
    }
  end

  @doc "Lists rule deployment audit entries for a pool."
  def list_pool_rule_deployments(pool_id, opts \\ []) do
    opts
    |> Keyword.put(:pool_id, pool_id)
    |> list_rule_deployments()
  end

  @doc "Counts sensors whose deployed rule version differs from the assigned ruleset version."
  def out_of_sync_count(pool_id) do
    case pool_assignment(pool_id) do
      %PoolRulesetAssignment{ruleset: %Ruleset{version: version}} ->
        Repo.aggregate(
          from(p in SensorPod,
            where: p.pool_id == ^pool_id,
            where:
              is_nil(p.last_deployed_rule_version) or p.last_deployed_rule_version != ^version
          ),
          :count,
          :id
        )

      nil ->
        0
    end
  end

  @doc "Returns per-sensor rule sync status for a pool."
  def sensor_sync_statuses(pool_id) do
    assignment = pool_assignment(pool_id)
    expected_version = assignment && assignment.ruleset && assignment.ruleset.version

    pool_id
    |> pool_sensors()
    |> Enum.map(fn sensor ->
      status =
        cond do
          is_nil(expected_version) -> :no_ruleset_assigned
          sensor.last_deployed_rule_version == expected_version -> :in_sync
          true -> :out_of_sync
        end

      %{
        sensor: sensor,
        deployed_version: sensor.last_deployed_rule_version,
        expected_version: expected_version,
        in_sync: status == :in_sync,
        status: status
      }
    end)
  end

  defp maybe_search(query, nil), do: query
  defp maybe_search(query, ""), do: query

  defp maybe_search(query, search) do
    search = search |> to_string() |> String.trim()
    sid_pattern = "#{search}%"
    message_pattern = "%#{String.downcase(search)}%"

    where(
      query,
      [r],
      fragment("CAST(? AS TEXT) LIKE ?", r.sid, ^sid_pattern) or
        like(fragment("lower(coalesce(?, ''))", r.message), ^message_pattern)
    )
  end

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, _field, ""), do: query

  defp maybe_filter(query, field, value) do
    where(query, [r], field(r, ^field) == ^value)
  end

  defp maybe_filter_repository(query, nil), do: query
  defp maybe_filter_repository(query, ""), do: query

  defp maybe_filter_repository(query, repository) do
    where(query, [r], r.repository_id == ^repository or r.repository_name == ^repository)
  end

  defp maybe_filter_pool_deployment(query, nil), do: query
  defp maybe_filter_pool_deployment(query, ""), do: query

  defp maybe_filter_pool_deployment(query, pool_id) do
    where(query, [a], a.target_type == "pool" and a.target_id == ^pool_id)
  end

  defp apply_sort(query, sort_by, sort_dir) do
    field = Map.get(@sort_fields, sort_by, :sid)
    direction = if sort_dir in [:desc, "desc", "DESC"], do: :desc, else: :asc

    order_by(query, [r], [{^direction, field(r, ^field)}, asc: r.sid])
  end

  defp opt(opts, key, default \\ nil)

  defp opt(opts, key, default) when is_list(opts) do
    Keyword.get(opts, key, default)
  end

  defp opt(opts, key, default) when is_map(opts) do
    Map.get(opts, key, Map.get(opts, to_string(key), default))
  end

  defp opt(_opts, _key, default), do: default

  defp run_repository_update(repository_id, actor, fetcher) do
    with %RuleRepository{} = repository <- Repo.get(RuleRepository, repository_id),
         {:ok, rules_data} <- fetcher.fetch_and_parse(repository.url),
         {:ok, counts} <- bulk_upsert_rules(rules_data, repository, actor),
         {:ok, _repository} <- mark_repository_success(repository) do
      broadcast_repositories({:repository_updated, repository.id})
      {:ok, counts}
    else
      nil ->
        {:error, :repository_not_found}

      {:error, reason} ->
        mark_repository_failed(repository_id, reason)
        {:error, reason}
    end
  end

  defp mark_repository_success(%RuleRepository{} = repository) do
    repository
    |> Repo.reload!()
    |> RuleRepository.update_status_changeset(%{
      last_updated_at: DateTime.utc_now() |> DateTime.truncate(:second),
      last_update_status: "success",
      last_update_error: nil,
      rule_count: repository_rule_count(repository.id)
    })
    |> Repo.update()
  end

  defp mark_repository_failed(repository_id, reason) do
    case Repo.get(RuleRepository, repository_id) do
      %RuleRepository{} = repository ->
        repository
        |> RuleRepository.update_status_changeset(%{
          last_updated_at: DateTime.utc_now() |> DateTime.truncate(:second),
          last_update_status: "failed",
          last_update_error: inspect(reason),
          rule_count: repository_rule_count(repository.id)
        })
        |> Repo.update()

        Audit.log(%{
          actor: "system",
          actor_type: "system",
          action: "repository_update_failed",
          target_type: "rule_repository",
          target_id: repository.id,
          result: "failure",
          detail: %{name: repository.name, error: inspect(reason)}
        })

        broadcast_repositories({:repository_update_failed, repository.id, reason})

      nil ->
        nil
    end
  end

  defp upsert_rule(repo, rule_data, repository) do
    attrs = rule_attrs(rule_data, repository)
    existing = repo.get_by(SuricataRule, sid: attrs.sid)

    cond do
      is_nil(existing) ->
        %SuricataRule{}
        |> SuricataRule.changeset(attrs)
        |> repo.insert()
        |> case do
          {:ok, _rule} -> {:ok, :added}
          {:error, changeset} -> {:error, changeset}
        end

      attrs.revision < existing.revision ->
        {:ok, :unchanged}

      upsert_changes(existing, attrs) == %{} ->
        {:ok, :unchanged}

      true ->
        existing
        |> SuricataRule.changeset(Map.merge(attrs, %{enabled: existing.enabled}))
        |> repo.update()
        |> case do
          {:ok, _rule} -> {:ok, :updated}
          {:error, changeset} -> {:error, changeset}
        end
    end
  end

  defp upsert_changes(existing, attrs) do
    attrs
    |> Map.drop([:enabled])
    |> Enum.reject(fn {field, value} -> Map.get(existing, field) == value end)
    |> Map.new()
  end

  defp rule_attrs(rule_data, repository) do
    %{
      sid: data_value(rule_data, :sid),
      message: data_value(rule_data, :message),
      raw_text: data_value(rule_data, :raw_text),
      category: data_value(rule_data, :category),
      classtype: data_value(rule_data, :classtype),
      severity: data_value(rule_data, :severity) || 2,
      revision: data_value(rule_data, :revision) || 1,
      enabled: data_value(rule_data, :enabled) != false,
      repository_id: repository.id,
      repository_name: repository.name
    }
  end

  defp dedupe_rules_data(rules_data) do
    rules_data
    |> Enum.reject(&(is_nil(data_value(&1, :sid)) or is_nil(data_value(&1, :raw_text))))
    |> Enum.reduce(%{}, fn rule_data, acc ->
      sid = data_value(rule_data, :sid)
      current = Map.get(acc, sid)

      if is_nil(current) or revision_value(rule_data) >= revision_value(current) do
        Map.put(acc, sid, rule_data)
      else
        acc
      end
    end)
    |> Map.values()
  end

  defp data_value(data, key) when is_map(data) do
    Map.get(data, key) || Map.get(data, to_string(key))
  end

  defp revision_value(data), do: data_value(data, :revision) || 1

  defp upsert_ruleset_override(%Ruleset{} = ruleset, sid, action, actor) do
    existing = Repo.get_by(RulesetRule, ruleset_id: ruleset.id, sid: sid)

    cond do
      existing && existing.action == action ->
        {:ok, existing}

      existing ->
        update_ruleset_override(ruleset, existing, action, actor)

      true ->
        insert_ruleset_override(ruleset, sid, action, actor)
    end
  end

  defp insert_ruleset_override(%Ruleset{} = ruleset, sid, action, actor) do
    Multi.new()
    |> Multi.insert(
      :override,
      RulesetRule.changeset(%RulesetRule{}, %{
        ruleset_id: ruleset.id,
        sid: sid,
        action: action
      })
    )
    |> Multi.update(:ruleset, ruleset_version_changeset(ruleset, actor))
    |> Audit.append_multi(fn %{override: override, ruleset: updated} ->
      ruleset_override_audit(updated, override, actor, "override_added")
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{override: override, ruleset: updated}} ->
        broadcast_rulesets({:ruleset_updated, Repo.preload(updated, :overrides)})
        {:ok, override}

      {:error, :override, changeset, _changes} ->
        {:error, changeset}

      {:error, :ruleset, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  defp update_ruleset_override(%Ruleset{} = ruleset, %RulesetRule{} = override, action, actor) do
    Multi.new()
    |> Multi.update(:override, RulesetRule.changeset(override, %{action: action}))
    |> Multi.update(:ruleset, ruleset_version_changeset(ruleset, actor))
    |> Audit.append_multi(fn %{override: updated_override, ruleset: updated} ->
      ruleset_override_audit(updated, updated_override, actor, "override_updated")
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{override: override, ruleset: updated}} ->
        broadcast_rulesets({:ruleset_updated, Repo.preload(updated, :overrides)})
        {:ok, override}

      {:error, :override, changeset, _changes} ->
        {:error, changeset}

      {:error, :ruleset, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  defp ruleset_override_audit(%Ruleset{} = ruleset, %RulesetRule{} = override, actor, change) do
    %{
      actor: actor_name(actor),
      actor_type: "user",
      action: "ruleset_updated",
      target_type: "ruleset",
      target_id: ruleset.id,
      result: "success",
      detail: %{
        name: ruleset.name,
        changes: [change],
        sid: override.sid,
        action: override.action,
        version: ruleset.version
      }
    }
  end

  defp ruleset_version_changeset(%Ruleset{} = ruleset, actor) do
    Ecto.Changeset.change(ruleset,
      version: (ruleset.version || 1) + 1,
      updated_by: actor_name(actor)
    )
  end

  defp assignment_count(ruleset_id) do
    Repo.aggregate(
      from(a in PoolRulesetAssignment, where: a.ruleset_id == ^ruleset_id),
      :count,
      :id
    )
  end

  defp deploy_rules(deployer, pool_id, rule_files, ruleset, actor, opts) do
    deploy_opts =
      opts
      |> Keyword.drop([:compiler, :deployer])
      |> Keyword.put_new(:version, ruleset.version)
      |> Keyword.put_new(:updated_by, actor_name(actor))

    deployer.deploy_to_pool(pool_id, rule_files, deploy_opts)
  end

  defp record_rule_deployment(assignment, ruleset, pool_id, actor, results) do
    success_ids = successful_pod_ids(results)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    pool = Repo.get(SensorPool, pool_id)

    Multi.new()
    |> maybe_update_successful_sensors(success_ids, ruleset.version, now)
    |> maybe_update_assignment(assignment, success_ids, ruleset.version)
    |> Audit.append_multi(fn _changes ->
      %{
        actor: actor_name(actor),
        actor_type: "user",
        action: "rules_deployed",
        target_type: "pool",
        target_id: pool_id,
        result: "success",
        detail: %{
          pool_name: pool && pool.name,
          ruleset_name: ruleset.name,
          ruleset_id: ruleset.id,
          version: ruleset.version,
          sensor_results: summarize_deployment_results(results)
        }
      }
    end)
    |> Repo.transaction()
  end

  defp maybe_update_successful_sensors(multi, [], _version, _now), do: multi

  defp maybe_update_successful_sensors(multi, sensor_ids, version, now) do
    Multi.update_all(
      multi,
      :updated_sensors,
      from(p in SensorPod, where: p.id in ^sensor_ids),
      set: [last_deployed_rule_version: version, last_deployed_at: now]
    )
  end

  defp maybe_update_assignment(multi, assignment, [], _version) do
    Multi.run(multi, :assignment, fn _repo, _changes -> {:ok, assignment} end)
  end

  defp maybe_update_assignment(multi, assignment, _success_ids, version) do
    Multi.update(
      multi,
      :assignment,
      PoolRulesetAssignment.changeset(assignment, %{deployed_rule_version: version})
    )
  end

  defp successful_pod_ids(results) do
    results
    |> Enum.filter(&match?({:ok, _response}, &1.result))
    |> Enum.map(& &1.pod_id)
  end

  defp summarize_deployment_results(results) do
    Enum.map(results, fn result ->
      %{
        pod_id: result.pod_id,
        pod_name: result.pod_name,
        result: inspect(result.result)
      }
    end)
  end

  defp pool_sensors(pool_id) do
    Repo.all(from(p in SensorPod, where: p.pool_id == ^pool_id, order_by: [asc: p.name]))
  end

  defp repository_rule_count(repository_id) do
    Repo.aggregate(from(r in SuricataRule, where: r.repository_id == ^repository_id), :count, :id)
  end

  defp total_pages(0, _page_size), do: 0
  defp total_pages(total_count, page_size), do: div(total_count + page_size - 1, page_size)

  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor), do: actor
  defp actor_name(_actor), do: "system"

  defp broadcast_rules(message),
    do: Phoenix.PubSub.broadcast(ConfigManager.PubSub, "rules", message)

  defp broadcast_repositories(message),
    do: Phoenix.PubSub.broadcast(ConfigManager.PubSub, "rule_repositories", message)

  defp broadcast_rulesets(message),
    do: Phoenix.PubSub.broadcast(ConfigManager.PubSub, "rulesets", message)

  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) do
    case Integer.parse(to_string(value)) do
      {int, _rest} -> int
      :error -> 0
    end
  end
end
