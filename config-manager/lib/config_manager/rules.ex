defmodule ConfigManager.Rules do
  @moduledoc "Rule Store management context for rules, categories, repositories, rulesets, and deployment."

  import Ecto.Query

  alias ConfigManager.Rules.SuricataRule
  alias ConfigManager.{Audit, Repo}
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

  defp total_pages(0, _page_size), do: 0
  defp total_pages(total_count, page_size), do: div(total_count + page_size - 1, page_size)

  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor), do: actor
  defp actor_name(_actor), do: "system"

  defp broadcast_rules(message),
    do: Phoenix.PubSub.broadcast(ConfigManager.PubSub, "rules", message)

  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) do
    case Integer.parse(to_string(value)) do
      {int, _rest} -> int
      :error -> 0
    end
  end
end
