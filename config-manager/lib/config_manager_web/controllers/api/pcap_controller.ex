defmodule ConfigManagerWeb.Api.PcapController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.{Audit, Pcap, Repo, SensorPod}
  alias ConfigManagerWeb.Api.Errors

  def update_config(conn, %{"pod_id" => pod_id} = params) do
    case Repo.get(SensorPod, pod_id) do
      nil ->
        log_config(conn, pod_id, "failure", %{reason: "not_found"})
        not_found(conn, "Sensor pod")

      %SensorPod{} = pod ->
        attrs = %{
          pcap_ring_size_mb: int_param(params, "pcap_ring_size_mb", nil),
          pre_alert_window_sec: int_param(params, "pre_alert_window_sec", nil),
          post_alert_window_sec: int_param(params, "post_alert_window_sec", nil),
          alert_severity_threshold: int_param(params, "alert_severity_threshold", nil)
        }

        case pod |> SensorPod.pcap_config_changeset(attrs) |> Repo.update() do
          {:ok, updated} ->
            log_config(conn, updated.id, "success", %{config: attrs})
            json(conn, %{data: sensor_config(updated)})

          {:error, changeset} ->
            log_config(conn, pod.id, "failure", %{errors: changeset_errors(changeset)})
            changeset_error(conn, changeset)
        end
    end
  end

  def update_config(conn, _params) do
    api_error(conn, :unprocessable_entity, "VALIDATION_FAILED", "pod_id is required")
  end

  def list_requests(conn, params) do
    result = Pcap.list_requests(params)

    json(conn, %{
      data: Enum.map(result.entries, &Pcap.request_json/1),
      meta: Map.take(result, [:page, :page_size, :total_count, :total_pages])
    })
  end

  def show_request(conn, %{"id" => id}) do
    case Pcap.get_request(id) do
      nil -> not_found(conn, "PCAP request")
      request -> json(conn, %{data: Pcap.request_json(request)})
    end
  end

  def manifest(conn, %{"id" => id}) do
    case Pcap.get_request(id) do
      nil ->
        not_found(conn, "PCAP request")

      request ->
        {:ok, manifest_json, _integrity_hash} =
          Pcap.export_manifest_json(request, current_actor(conn), format_ip(conn.remote_ip))

        json(conn, Jason.decode!(manifest_json))
    end
  end

  def download(conn, %{"id" => id}) do
    case Pcap.get_request(id) do
      nil ->
        not_found(conn, "PCAP request")

      request ->
        case Pcap.download_pcap(request, current_actor(conn), format_ip(conn.remote_ip)) do
          {:ok, download} ->
            conn
            |> put_resp_content_type(download.content_type)
            |> put_resp_header(
              "content-disposition",
              ~s(attachment; filename="#{download.filename}")
            )
            |> send_resp(200, download.body)

          {:error, :not_ready} ->
            api_error(conn, :conflict, "PCAP_NOT_READY", "PCAP request is not ready for download")

          {:error, {:expired, _request}} ->
            api_error(conn, :gone, "PCAP_EXPIRED", "PCAP request has expired")

          {:error, reason} ->
            api_error(conn, :bad_gateway, "PCAP_DOWNLOAD_FAILED", format_reason(reason))
        end
    end
  end

  def carve(conn, params) do
    case Pcap.submit_carve(params, current_actor(conn)) do
      {:ok, request} ->
        conn
        |> put_status(:accepted)
        |> json(%{data: Pcap.request_json(request)})

      {:error, :not_found} ->
        not_found(conn, "Sensor pod")

      {:error, {:validation, errors}} ->
        api_error(conn, :unprocessable_entity, "VALIDATION_FAILED", "Validation failed", %{
          fields: errors
        })

      {:error, {:sensor_unreachable, request}} ->
        conn
        |> put_status(:service_unavailable)
        |> json(
          Errors.body(conn, "SENSOR_UNREACHABLE", "Sensor pod has no reachable control API host")
          |> Map.put(:data, Pcap.request_json(request))
        )

      {:error, {:validation_error, request}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(
          Errors.body(conn, "SENSOR_VALIDATION_FAILED", request.error_reason)
          |> Map.put(:data, Pcap.request_json(request))
        )

      {:error, {_reason, request}} ->
        conn
        |> put_status(:bad_gateway)
        |> json(
          Errors.body(conn, "PCAP_CARVE_FAILED", request.error_reason)
          |> Map.put(:data, Pcap.request_json(request))
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        changeset_error(conn, changeset)

      {:error, reason} ->
        action_error(conn, reason)
    end
  end

  defp sensor_config(pod) do
    %{
      pod_id: pod.id,
      pcap_ring_size_mb: pod.pcap_ring_size_mb,
      pre_alert_window_sec: pod.pre_alert_window_sec,
      post_alert_window_sec: pod.post_alert_window_sec,
      alert_severity_threshold: pod.alert_severity_threshold
    }
  end

  defp log_config(conn, pod_id, result, detail) do
    Audit.log(%{
      actor: actor_name(conn),
      actor_type: actor_type(conn),
      action: "pcap_config_changed",
      target_type: "sensor_pod",
      target_id: pod_id,
      result: result,
      detail: Map.put(detail, :required_permission, "pcap:configure")
    })
  end

  defp format_ip(tuple) when is_tuple(tuple) do
    tuple
    |> :inet.ntoa()
    |> to_string()
  end

  defp format_ip(_ip), do: nil
end
