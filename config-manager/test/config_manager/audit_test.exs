defmodule ConfigManager.AuditTest do
  use ConfigManager.DataCase, async: false
  use PropCheck

  alias ConfigManager.{Audit, AuditEntry, Repo}
  alias Ecto.Multi

  test "log writes structurally valid audit entry and encodes map detail" do
    assert {:ok, entry} =
             Audit.log(%{
               actor: "user:1",
               actor_type: "user",
               action: "sensor_reloaded",
               target_type: "sensor",
               target_id: "sensor-1",
               result: "success",
               detail: %{service: "zeek"}
             })

    assert entry.id
    assert entry.timestamp
    assert entry.detail == ~s({"service":"zeek"})

    stored = Repo.get!(AuditEntry, entry.id)
    assert stored.actor == "user:1"
    assert Jason.decode!(stored.detail) == %{"service" => "zeek"}
  end

  test "list_entries paginates newest first and coerces invalid page options" do
    base = DateTime.utc_now() |> DateTime.add(365 * 24 * 60 * 60, :second)
    old = insert_entry!("old", DateTime.add(base, -60, :second))
    middle = insert_entry!("middle", DateTime.add(base, -30, :second))
    new = insert_entry!("new", base)

    assert [%AuditEntry{action: "new"}, %AuditEntry{action: "middle"}] =
             Audit.list_entries(page: 1, page_size: 2)

    assert [%AuditEntry{action: "old"} | _entries] = Audit.list_entries(page: 2, page_size: 2)

    assert [%AuditEntry{action: "new"} | _] = Audit.list_entries(page: "bad", page_size: "bad")

    assert Repo.get!(AuditEntry, old.id)
    assert Repo.get!(AuditEntry, middle.id)
    assert Repo.get!(AuditEntry, new.id)
  end

  test "list_entries pages do not duplicate entries and keep descending order" do
    base = DateTime.utc_now() |> DateTime.add(366 * 24 * 60 * 60, :second)

    inserted =
      for index <- 1..12 do
        insert_entry!("paged-#{index}", DateTime.add(base, -index, :second))
      end

    page_1 = Audit.list_entries(page: 1, page_size: 5)
    page_2 = Audit.list_entries(page: 2, page_size: 5)
    page_3 = Audit.list_entries(page: 3, page_size: 5)

    expected_ids = inserted |> Enum.map(& &1.id) |> MapSet.new()
    returned = Enum.filter(page_1 ++ page_2 ++ page_3, &MapSet.member?(expected_ids, &1.id))

    assert length(returned) == length(inserted)
    assert returned |> Enum.map(& &1.id) |> Enum.uniq() |> length() == length(inserted)
    assert returned == Enum.sort_by(returned, & &1.timestamp, {:desc, DateTime})
  end

  test "list_entries filters by audit fields and date range" do
    base = ~U[2026-05-22 12:00:00Z]

    matching =
      insert_entry!("filtered_action", base,
        actor: "alice",
        target_type: "pool",
        target_id: "pool-1"
      )

    _wrong_actor =
      insert_entry!("filtered_action", DateTime.add(base, -60, :second),
        actor: "bob",
        target_type: "pool",
        target_id: "pool-1"
      )

    _wrong_date =
      insert_entry!("filtered_action", DateTime.add(base, -24 * 60 * 60, :second),
        actor: "alice",
        target_type: "pool",
        target_id: "pool-1"
      )

    filters = %{
      "actor" => "alice",
      "action" => "filtered_action",
      "target_type" => "pool",
      "target_id" => "pool-1",
      "result" => "success",
      "start_date" => "2026-05-22",
      "end_date" => "2026-05-22"
    }

    assert [entry] = Audit.list_entries(filters: filters)
    assert entry.id == matching.id
    assert Audit.count_entries(filters: filters) == 1
  end

  test "export_entries returns filtered JSON and CSV without deleting audit entries" do
    timestamp = ~U[2026-05-22 13:00:00Z]

    _entry =
      insert_entry!("exported_action", timestamp,
        actor: "exporter",
        detail: %{note: "quoted,value"}
      )

    filters = %{action: "exported_action"}

    assert {:ok, "application/json", json} = Audit.export_entries([filters: filters], :json)

    assert [%{"action" => "exported_action", "detail" => %{"note" => "quoted,value"}}] =
             Jason.decode!(json)

    assert {:ok, "text/csv", csv} = Audit.export_entries([filters: filters], :csv)
    assert csv =~ "id,timestamp,actor,actor_type,action,target_type,target_id,result,detail"
    assert csv =~ "exported_action"
    assert csv =~ "\"{\"\"note\"\":\"\"quoted,value\"\"}\""

    assert Repo.aggregate(AuditEntry, :count) >= 1
  end

  test "append_multi writes an audit entry in the caller transaction" do
    assert {:ok, %{audit: entry}} =
             Multi.new()
             |> Audit.append_multi(fn _changes ->
               %{
                 actor: "system",
                 actor_type: "system",
                 action: "transactional_event",
                 target_type: "auth",
                 target_id: "auth-1",
                 result: "success",
                 detail: %{mode: "transactional"}
               }
             end)
             |> Repo.transaction()

    stored = Repo.get!(AuditEntry, entry.id)
    assert stored.action == "transactional_event"
    assert Jason.decode!(stored.detail) == %{"mode" => "transactional"}
  end

  property "Property 13: Audit log filters return only matching entries",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      Repo.delete_all(AuditEntry)

      base = ~U[2026-05-22 12:00:00Z]
      batch = "audit-filter-#{code}-#{System.unique_integer([:positive])}"

      entries =
        for index <- 0..15 do
          insert_entry!(
            "action-#{rem(index + code, 4)}-#{batch}",
            DateTime.add(base, index * 60, :second),
            actor: "actor-#{rem(index + div(code, 2), 3)}-#{batch}",
            actor_type: Enum.at(~w(user api_token system anonymous), rem(index + code, 4)),
            target_type: "target-#{rem(index + div(code, 3), 3)}",
            target_id: "target-id-#{rem(index + code, 5)}-#{batch}",
            result: Enum.at(~w(success failure), rem(index + code, 2)),
            detail: %{batch: batch, index: index}
          )
        end

      filters = generated_filters(code, entries, base)

      expected =
        entries
        |> Enum.filter(&matches_filters?(&1, filters))
        |> Enum.sort_by(&{&1.timestamp, &1.id}, :desc)

      returned = Audit.list_entries(filters: filters, page_size: 100)

      Enum.map(returned, & &1.id) == Enum.map(expected, & &1.id) and
        Audit.count_entries(filters: filters) == length(expected) and
        Enum.all?(returned, &matches_filters?(&1, filters))
    end
  end

  defp insert_entry!(action, timestamp, attrs \\ []) do
    attrs = Map.new(attrs)

    %AuditEntry{}
    |> AuditEntry.changeset(%{
      timestamp: DateTime.truncate(timestamp, :microsecond),
      actor: Map.get(attrs, :actor, "test"),
      actor_type: Map.get(attrs, :actor_type, "system"),
      action: action,
      target_type: Map.get(attrs, :target_type),
      target_id: Map.get(attrs, :target_id),
      result: Map.get(attrs, :result, "success"),
      detail: maybe_encode_detail(Map.get(attrs, :detail))
    })
    |> Repo.insert!()
  end

  defp maybe_encode_detail(nil), do: nil
  defp maybe_encode_detail(detail) when is_binary(detail), do: detail
  defp maybe_encode_detail(detail), do: Jason.encode!(detail)

  defp generated_filters(code, entries, base) do
    reference = Enum.at(entries, rem(code, length(entries)))
    start_offset = rem(div(code, 7), 8)
    end_offset = start_offset + 1 + rem(div(code, 11), 8)

    %{}
    |> maybe_put_filter(rem(code, 2) == 0, "actor", reference.actor)
    |> maybe_put_filter(rem(code, 3) == 0, "action", reference.action)
    |> maybe_put_filter(rem(code, 5) == 0, "target_type", reference.target_type)
    |> maybe_put_filter(rem(code, 7) == 0, "target_id", reference.target_id)
    |> maybe_put_filter(rem(code, 11) == 0, "result", reference.result)
    |> maybe_put_filter(
      rem(code, 13) == 0,
      "start_date",
      DateTime.add(base, start_offset * 60, :second)
    )
    |> maybe_put_filter(
      rem(code, 17) == 0,
      "end_date",
      DateTime.add(base, end_offset * 60, :second)
    )
  end

  defp maybe_put_filter(filters, true, key, value), do: Map.put(filters, key, value)
  defp maybe_put_filter(filters, false, _key, _value), do: filters

  defp matches_filters?(%AuditEntry{} = entry, filters) do
    Enum.all?(filters, fn
      {"actor", value} ->
        entry.actor == value

      {"action", value} ->
        entry.action == value

      {"target_type", value} ->
        entry.target_type == value

      {"target_id", value} ->
        entry.target_id == value

      {"result", value} ->
        entry.result == value

      {"start_date", %DateTime{} = value} ->
        DateTime.compare(entry.timestamp, value) in [:eq, :gt]

      {"end_date", %DateTime{} = value} ->
        DateTime.compare(entry.timestamp, value) == :lt
    end)
  end
end
