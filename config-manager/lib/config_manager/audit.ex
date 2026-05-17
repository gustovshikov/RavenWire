defmodule ConfigManager.Audit do
  @moduledoc "Audit log writer and query helpers."

  import Ecto.Query

  alias ConfigManager.{AuditEntry, Repo}
  alias Ecto.Multi

  def log(attrs) do
    attrs
    |> entry_changeset()
    |> Repo.insert()
  end

  def append_multi(%Multi{} = multi, attrs_or_fun) do
    append_multi(multi, :audit, attrs_or_fun)
  end

  def append_multi(%Multi{} = multi, name, attrs_or_fun) do
    Multi.insert(multi, name, fn changes ->
      attrs_or_fun
      |> resolve_attrs(changes)
      |> entry_changeset()
    end)
  end

  def list_entries(opts \\ []) do
    page = max(to_int(Keyword.get(opts, :page, 1)), 1)
    page_size = max(to_int(Keyword.get(opts, :page_size, 50)), 1)

    AuditEntry
    |> order_by([a], desc: a.timestamp)
    |> limit(^page_size)
    |> offset(^((page - 1) * page_size))
    |> Repo.all()
  end

  defp entry_changeset(attrs) do
    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:timestamp, DateTime.utc_now())
      |> encode_detail()

    AuditEntry.changeset(%AuditEntry{}, attrs)
  end

  defp resolve_attrs(fun, changes) when is_function(fun, 1), do: fun.(changes)
  defp resolve_attrs(attrs, _changes), do: attrs

  defp encode_detail(%{detail: detail} = attrs) when is_map(detail) or is_list(detail) do
    %{attrs | detail: Jason.encode!(detail)}
  end

  defp encode_detail(attrs), do: attrs

  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> 1
    end
  end

  defp to_int(_), do: 1
end
