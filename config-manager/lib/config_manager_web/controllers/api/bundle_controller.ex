defmodule ConfigManagerWeb.Api.BundleController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.{Audit, Repo, SensorAgentClient, SensorPod}

  def create(conn, %{"pod_id" => pod_id}) do
    case Repo.get(SensorPod, pod_id) do
      nil ->
        log_bundle(conn, pod_id, "failure", %{reason: "not_found"})
        not_found(conn, "Sensor pod")

      %SensorPod{} = pod ->
        case SensorAgentClient.request_support_bundle(pod) do
          {:ok, result} ->
            log_bundle(conn, pod.id, "success", %{response: result})
            json(conn, %{data: result})

          {:error, reason} ->
            log_bundle(conn, pod.id, "failure", %{reason: format_reason(reason)})
            action_error(conn, reason)
        end
    end
  end

  def create(conn, _params) do
    api_error(conn, :unprocessable_entity, "VALIDATION_FAILED", "pod_id is required")
  end

  defp log_bundle(conn, pod_id, result, detail) do
    Audit.log(%{
      actor: actor_name(conn),
      actor_type: actor_type(conn),
      action: "support_bundle_requested",
      target_type: "sensor_pod",
      target_id: pod_id,
      result: result,
      detail: Map.put(detail, :required_permission, "bundle:download")
    })
  end
end
