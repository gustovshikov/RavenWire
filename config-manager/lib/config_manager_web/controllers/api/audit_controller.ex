defmodule ConfigManagerWeb.Api.AuditController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Audit

  def index(conn, params) do
    opts = audit_opts(params)

    json(conn, %{
      data: Audit.list_entries(opts) |> Enum.map(&entry_json/1),
      meta: %{
        page: Keyword.fetch!(opts, :page),
        page_size: Keyword.fetch!(opts, :page_size),
        total_count: Audit.count_entries(filters: Keyword.fetch!(opts, :filters))
      }
    })
  end

  def export(conn, params) do
    format = params["format"] || "json"

    Audit.log(%{
      actor: actor_name(conn),
      actor_type: actor_type(conn),
      action: "audit_export",
      target_type: "audit_log",
      target_id: "export",
      result: "success",
      detail: %{filters: audit_filters(params), format: format}
    })

    case Audit.export_entries([filters: audit_filters(params)], format) do
      {:ok, content_type, body} ->
        conn
        |> put_resp_content_type(content_type)
        |> send_resp(200, body)

      {:error, {:too_many_entries, count, limit}} ->
        api_error(
          conn,
          :unprocessable_entity,
          "EXPORT_TOO_LARGE",
          "Export has too many entries",
          %{
            count: count,
            limit: limit
          }
        )

      {:error, :unsupported_format} ->
        api_error(conn, :unprocessable_entity, "UNSUPPORTED_FORMAT", "Unsupported export format")
    end
  end

  defp audit_opts(params) do
    page_opts(params, 50)
    |> Keyword.put(:filters, audit_filters(params))
  end

  defp audit_filters(params) do
    Map.take(
      params,
      ~w(actor action target_type target_id result from from_date start_date to to_date end_date)
    )
  end

  defp entry_json(entry) do
    %{
      id: entry.id,
      timestamp: entry.timestamp,
      actor: entry.actor,
      actor_type: entry.actor_type,
      action: entry.action,
      target_type: entry.target_type,
      target_id: entry.target_id,
      result: entry.result,
      detail: decode_detail(entry.detail)
    }
  end

  defp decode_detail(nil), do: nil

  defp decode_detail(detail) do
    case Jason.decode(detail) do
      {:ok, decoded} -> decoded
      _ -> detail
    end
  end
end
