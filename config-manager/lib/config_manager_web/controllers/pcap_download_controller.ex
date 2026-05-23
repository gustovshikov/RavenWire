defmodule ConfigManagerWeb.PcapDownloadController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Pcap

  def download(conn, %{"id" => id}) do
    with {:ok, request} <- fetch_request(conn, id),
         {:ok, download} <-
           Pcap.download_pcap(request, conn.assigns.current_user, format_ip(conn.remote_ip)) do
      conn
      |> put_resp_content_type(download.content_type)
      |> put_resp_header("content-disposition", ~s(attachment; filename="#{download.filename}"))
      |> send_resp(200, download.body)
    else
      {:error, :not_found} ->
        send_resp(conn, 404, "PCAP request not found")

      {:error, :not_ready} ->
        conn |> put_status(:conflict) |> text("PCAP request is not ready for download")

      {:error, {:expired, _request}} ->
        conn |> put_status(:gone) |> text("PCAP request has expired")

      {:error, reason} ->
        conn |> put_status(:bad_gateway) |> text("PCAP download failed: #{inspect(reason)}")
    end
  end

  def export_manifest(conn, %{"id" => id}) do
    with {:ok, request} <- fetch_request(conn, id),
         {:ok, json, _hash} <-
           Pcap.export_manifest_json(
             request,
             conn.assigns.current_user,
             format_ip(conn.remote_ip)
           ) do
      conn
      |> put_resp_content_type("application/json")
      |> put_resp_header(
        "content-disposition",
        ~s(attachment; filename="pcap-manifest-#{request.id}.json")
      )
      |> send_resp(200, json)
    else
      {:error, :not_found} -> send_resp(conn, 404, "PCAP request not found")
    end
  end

  defp fetch_request(conn, id) do
    case Pcap.get_request_for_actor(id, conn.assigns.current_user) do
      nil -> {:error, :not_found}
      request -> {:ok, request}
    end
  end

  defp format_ip(tuple) when is_tuple(tuple), do: tuple |> :inet.ntoa() |> to_string()
  defp format_ip(_ip), do: nil
end
