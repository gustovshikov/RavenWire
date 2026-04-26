defmodule ConfigManagerWeb.SupportBundleController do
  @moduledoc """
  HTTP controller for downloading support bundle archives from Sensor_Agents.

  The browser navigates directly to this endpoint so the file download is
  handled natively without going through LiveView.

  Requirements: 25.4
  """

  use ConfigManagerWeb, :controller

  import Ecto.Query

  alias ConfigManager.Repo
  alias ConfigManager.SensorPod
  alias ConfigManager.SensorAgentClient

  @doc """
  Downloads a support bundle archive from the Sensor_Agent for the given pod.

  Path params: `pod_id`
  Query params: `path` — the bundle path returned by the generate action
  """
  def download(conn, %{"pod_id" => pod_id, "path" => bundle_path}) do
    case Repo.one(from p in SensorPod, where: p.id == ^pod_id and p.status == "enrolled") do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pod not found or not enrolled"})

      pod ->
        case SensorAgentClient.download_support_bundle(pod, bundle_path) do
          {:ok, data} ->
            timestamp = DateTime.utc_now() |> Calendar.strftime("%Y%m%d-%H%M%S")
            filename = "support-bundle-#{pod.name}-#{timestamp}.tar.gz"

            conn
            |> put_resp_content_type("application/gzip")
            |> put_resp_header("content-disposition", ~s(attachment; filename="#{filename}"))
            |> send_resp(200, data)

          {:error, reason} ->
            conn
            |> put_status(:bad_gateway)
            |> json(%{error: "Failed to download support bundle: #{format_error(reason)}"})
        end
    end
  end

  def download(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: path"})
  end

  defp format_error({:http_error, status, body}), do: "HTTP #{status}: #{body}"
  defp format_error(:no_control_api_host), do: "Pod has no control API host configured"
  defp format_error(reason), do: inspect(reason)
end
