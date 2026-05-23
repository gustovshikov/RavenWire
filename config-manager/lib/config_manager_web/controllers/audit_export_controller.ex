defmodule ConfigManagerWeb.AuditExportController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Audit

  def download(conn, params) do
    format = Map.get(params, "format", "json")
    filters = clean_filters(params)
    user = conn.assigns.current_user

    with {:ok, content_type, body} <- Audit.export_entries([filters: filters], format) do
      case log_export(user, filters, format) do
        {:ok, _entry} ->
          conn
          |> put_resp_content_type(content_type)
          |> put_resp_header(
            "content-disposition",
            ~s(attachment; filename="#{filename(format)}")
          )
          |> send_resp(200, body)

        {:error, _changeset} ->
          conn
          |> put_status(:internal_server_error)
          |> html("Audit export failed because the export audit entry could not be written.")
      end
    else
      {:error, {:too_many_entries, count, limit}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> html(
          "Export would include #{count} records, which exceeds the #{limit} record limit. Narrow the date range or filters."
        )

      {:error, :unsupported_format} ->
        conn
        |> put_status(:bad_request)
        |> html("Unsupported audit export format.")
    end
  end

  defp log_export(user, filters, format) do
    Audit.log(%{
      actor: user.username,
      actor_type: "user",
      action: "audit_export",
      target_type: "audit_log",
      target_id: "export",
      result: "success",
      detail: %{filters: filters, format: format}
    })
  end

  defp clean_filters(params) do
    params
    |> Map.take([
      "start_date",
      "end_date",
      "actor",
      "action",
      "target_type",
      "target_id",
      "result"
    ])
    |> Enum.reject(fn {_key, value} -> is_nil(value) or String.trim(to_string(value)) == "" end)
    |> Map.new(fn {key, value} -> {key, String.trim(to_string(value))} end)
  end

  defp filename("csv"), do: timestamped_filename("csv")
  defp filename(:csv), do: timestamped_filename("csv")
  defp filename(_format), do: timestamped_filename("json")

  defp timestamped_filename(extension) do
    timestamp = DateTime.utc_now() |> Calendar.strftime("%Y%m%d-%H%M%S")
    "ravenwire-audit-#{timestamp}.#{extension}"
  end
end
