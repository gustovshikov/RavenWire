defmodule ConfigManager.AuditTest do
  use ConfigManager.DataCase, async: false

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

  defp insert_entry!(action, timestamp) do
    %AuditEntry{}
    |> AuditEntry.changeset(%{
      timestamp: DateTime.truncate(timestamp, :microsecond),
      actor: "test",
      actor_type: "system",
      action: action,
      result: "success"
    })
    |> Repo.insert!()
  end
end
