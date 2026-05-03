defmodule ConfigManager.Audit do
  @moduledoc "Audit log writer and query helpers."

  import Ecto.Query

  alias ConfigManager.{AuditEntry, Repo}

  def log(attrs) do
    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:timestamp, DateTime.utc_now())
      |> encode_detail()

    %AuditEntry{}
    |> AuditEntry.changeset(attrs)
    |> Repo.insert()
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
