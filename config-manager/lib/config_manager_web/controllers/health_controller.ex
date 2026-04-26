defmodule ConfigManagerWeb.HealthController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Health.Registry

  def show(conn, %{"pod_id" => pod_id}) do
    case Registry.get_pod(pod_id) do
      nil ->
        conn |> put_status(404) |> json(%{error: %{code: "NOT_FOUND", message: "Sensor pod not found"}})

      pod ->
        json(conn, pod)
    end
  end
end
