defmodule ConfigManagerWeb.Api.EnrollmentController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.{Audit, Enrollment}

  def approve(conn, %{"id" => id}) do
    case Enrollment.approve(id) do
      {:ok, bundle} ->
        log_enrollment(conn, "enrollment_approved", id, "success", %{})
        json(conn, %{data: bundle})

      {:error, reason} ->
        log_enrollment(conn, "enrollment_approved", id, "failure", %{
          reason: format_reason(reason)
        })

        action_error(conn, reason)
    end
  end

  def deny(conn, %{"id" => id}) do
    case Enrollment.deny(id) do
      {:ok, :denied} ->
        log_enrollment(conn, "enrollment_denied", id, "success", %{})
        json(conn, %{data: %{id: id, status: "denied"}})

      {:error, :not_found} ->
        log_enrollment(conn, "enrollment_denied", id, "failure", %{reason: "not_found"})
        not_found(conn, "Enrollment")

      {:error, reason} ->
        log_enrollment(conn, "enrollment_denied", id, "failure", %{reason: format_reason(reason)})
        action_error(conn, reason)
    end
  end

  defp log_enrollment(conn, action, id, result, detail) do
    Audit.log(%{
      actor: actor_name(conn),
      actor_type: actor_type(conn),
      action: action,
      target_type: "sensor_pod",
      target_id: id,
      result: result,
      detail: detail
    })
  end
end
