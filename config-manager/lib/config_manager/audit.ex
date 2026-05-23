defmodule ConfigManager.Audit do
  @moduledoc "Audit log writer and query helpers."

  import Ecto.Query

  alias ConfigManager.{AuditEntry, Repo}
  alias Ecto.Multi

  @export_limit 100_000
  @export_fields ~w(id timestamp actor actor_type action target_type target_id result detail)

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
    filters = filters_from_opts(opts)

    AuditEntry
    |> apply_filters(filters)
    |> order_by([a], desc: a.timestamp, desc: a.id)
    |> limit(^page_size)
    |> offset(^((page - 1) * page_size))
    |> Repo.all()
  end

  def count_entries(opts \\ []) do
    opts
    |> filters_from_opts()
    |> then(fn filters ->
      AuditEntry
      |> apply_filters(filters)
      |> Repo.aggregate(:count)
    end)
  end

  def export_entries(opts \\ [], format \\ :json) do
    filters = filters_from_opts(opts)
    count = count_entries(filters: filters)

    if count > @export_limit do
      {:error, {:too_many_entries, count, @export_limit}}
    else
      entries =
        AuditEntry
        |> apply_filters(filters)
        |> order_by([a], desc: a.timestamp, desc: a.id)
        |> limit(^@export_limit)
        |> Repo.all()

      encode_export(entries, format)
    end
  end

  def export_limit, do: @export_limit

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

  defp filters_from_opts(opts) when is_list(opts) do
    case Keyword.fetch(opts, :filters) do
      {:ok, filters} ->
        filters_from_opts(filters)

      :error ->
        opts
        |> Keyword.drop([:page, :page_size])
        |> Map.new()
        |> filters_from_opts()
    end
  end

  defp filters_from_opts(filters) when is_map(filters) do
    filters
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      normalized_key = key |> to_string() |> String.trim()
      normalized_value = normalize_filter_value(value)

      if normalized_value == "" do
        acc
      else
        Map.put(acc, normalized_key, normalized_value)
      end
    end)
  end

  defp filters_from_opts(_filters), do: %{}

  defp normalize_filter_value(%DateTime{} = value), do: value
  defp normalize_filter_value(%Date{} = value), do: value
  defp normalize_filter_value(value) when is_binary(value), do: String.trim(value)
  defp normalize_filter_value(value), do: value

  defp apply_filters(query, filters) do
    filters
    |> Enum.reduce(query, fn
      {key, value}, query when key in ["actor", "action", "target_type", "target_id", "result"] ->
        where(query, [a], field(a, ^String.to_existing_atom(key)) == ^value)

      {key, value}, query when key in ["from", "from_date", "start_date"] ->
        case parse_start_datetime(value) do
          nil -> query
          datetime -> where(query, [a], a.timestamp >= ^datetime)
        end

      {key, value}, query when key in ["to", "to_date", "end_date"] ->
        case parse_end_datetime(value) do
          nil -> query
          datetime -> where(query, [a], a.timestamp < ^datetime)
        end

      _filter, query ->
        query
    end)
  end

  defp parse_start_datetime(%DateTime{} = value), do: value

  defp parse_start_datetime(%Date{} = value) do
    value
    |> DateTime.new!(~T[00:00:00], "Etc/UTC")
    |> DateTime.truncate(:microsecond)
  end

  defp parse_start_datetime(value) when is_binary(value) do
    with {:ok, date} <- Date.from_iso8601(value) do
      parse_start_datetime(date)
    else
      _ ->
        case DateTime.from_iso8601(value) do
          {:ok, datetime, _offset} -> DateTime.truncate(datetime, :microsecond)
          _ -> nil
        end
    end
  end

  defp parse_start_datetime(_value), do: nil

  defp parse_end_datetime(%DateTime{} = value), do: value

  defp parse_end_datetime(%Date{} = value) do
    value
    |> Date.add(1)
    |> parse_start_datetime()
  end

  defp parse_end_datetime(value) when is_binary(value) do
    with {:ok, date} <- Date.from_iso8601(value) do
      parse_end_datetime(date)
    else
      _ ->
        case DateTime.from_iso8601(value) do
          {:ok, datetime, _offset} -> DateTime.truncate(datetime, :microsecond)
          _ -> nil
        end
    end
  end

  defp parse_end_datetime(_value), do: nil

  defp encode_export(entries, format) when format in [:json, "json"] do
    {:ok, "application/json", Jason.encode!(Enum.map(entries, &export_map/1))}
  end

  defp encode_export(entries, format) when format in [:csv, "csv"] do
    body =
      [
        Enum.join(@export_fields, ",")
        | Enum.map(entries, &csv_row/1)
      ]
      |> Enum.join("\n")

    {:ok, "text/csv", body <> "\n"}
  end

  defp encode_export(_entries, _format), do: {:error, :unsupported_format}

  defp export_map(%AuditEntry{} = entry) do
    %{
      id: entry.id,
      timestamp: format_timestamp(entry.timestamp),
      actor: entry.actor,
      actor_type: entry.actor_type,
      action: entry.action,
      target_type: entry.target_type,
      target_id: entry.target_id,
      result: entry.result,
      detail: decode_detail(entry.detail)
    }
  end

  defp csv_row(%AuditEntry{} = entry) do
    entry
    |> export_map()
    |> Map.update!(:detail, &Jason.encode!/1)
    |> then(fn row ->
      @export_fields
      |> Enum.map(fn field -> csv_escape(Map.get(row, String.to_existing_atom(field))) end)
      |> Enum.join(",")
    end)
  end

  defp decode_detail(nil), do: nil
  defp decode_detail(""), do: nil

  defp decode_detail(detail) when is_binary(detail) do
    case Jason.decode(detail) do
      {:ok, decoded} -> decoded
      _ -> detail
    end
  end

  defp format_timestamp(nil), do: nil
  defp format_timestamp(%DateTime{} = timestamp), do: DateTime.to_iso8601(timestamp)

  defp csv_escape(nil), do: ""
  defp csv_escape(value) when not is_binary(value), do: value |> to_string() |> csv_escape()

  defp csv_escape(value) do
    escaped = String.replace(value, "\"", "\"\"")

    if String.contains?(escaped, [",", "\"", "\n", "\r"]) do
      ~s("#{escaped}")
    else
      escaped
    end
  end
end
