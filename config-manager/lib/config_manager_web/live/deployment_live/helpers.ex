defmodule ConfigManagerWeb.DeploymentLive.Helpers do
  @moduledoc false

  alias ConfigManager.Auth.Policy
  alias ConfigManager.Deployments.Deployment
  alias ConfigManagerWeb.Formatters

  def can_manage_deployments?(nil), do: false
  def can_manage_deployments?(user), do: Policy.has_permission?(user.role, "deployments:manage")

  def active_deployment?(%Deployment{status: status}), do: status in Deployment.active_statuses()
  def active_deployment?(_deployment), do: false

  def rollback_status?(%Deployment{status: status}), do: status in ["successful", "failed"]
  def rollback_status?(_deployment), do: false

  def status_label(nil), do: "Unknown"

  def status_label(status) when is_atom(status) do
    status
    |> Atom.to_string()
    |> status_label()
  end

  def status_label(status) do
    status
    |> to_string()
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map_join(" ", &String.capitalize/1)
  end

  def status_class("successful"), do: "bg-green-100 text-green-800"
  def status_class("success"), do: "bg-green-100 text-green-800"
  def status_class("in_sync"), do: "bg-green-100 text-green-800"
  def status_class(:in_sync), do: "bg-green-100 text-green-800"
  def status_class("pending"), do: "bg-gray-100 text-gray-700"
  def status_class("validating"), do: "bg-blue-100 text-blue-800"
  def status_class("deploying"), do: "bg-blue-100 text-blue-800"
  def status_class("pushing"), do: "bg-blue-100 text-blue-800"
  def status_class("skipped"), do: "bg-gray-100 text-gray-700"
  def status_class("rolled_back"), do: "bg-purple-100 text-purple-800"
  def status_class("cancelled"), do: "bg-yellow-100 text-yellow-900"
  def status_class("failed"), do: "bg-red-100 text-red-800"
  def status_class("unreachable"), do: "bg-red-100 text-red-800"
  def status_class("drift_detected"), do: "bg-yellow-100 text-yellow-900"
  def status_class(:drift_detected), do: "bg-yellow-100 text-yellow-900"
  def status_class("never_deployed"), do: "bg-gray-100 text-gray-700"
  def status_class(:never_deployed), do: "bg-gray-100 text-gray-700"
  def status_class(_status), do: "bg-gray-100 text-gray-700"

  def duration(%Deployment{started_at: nil}), do: Formatters.display(nil)
  def duration(%Deployment{completed_at: nil}), do: "Running"

  def duration(%Deployment{started_at: started_at, completed_at: completed_at}) do
    seconds = DateTime.diff(to_datetime(completed_at), to_datetime(started_at), :second)

    cond do
      seconds < 1 -> "<1s"
      seconds < 60 -> "#{seconds}s"
      seconds < 3_600 -> "#{div(seconds, 60)}m #{rem(seconds, 60)}s"
      true -> "#{div(seconds, 3_600)}h #{div(rem(seconds, 3_600), 60)}m"
    end
  end

  def result_summary(summary) when is_map(summary) do
    [
      summary_part(summary, :success, "ok"),
      summary_part(summary, :failed, "failed"),
      summary_part(summary, :unreachable, "unreachable"),
      summary_part(summary, :pending, "pending"),
      summary_part(summary, :pushing, "pushing"),
      summary_part(summary, :skipped, "skipped")
    ]
    |> Enum.reject(&is_nil/1)
    |> case do
      [] -> "No results"
      parts -> Enum.join(parts, ", ")
    end
  end

  def result_summary(_summary), do: "No results"

  def drift_summary_label(%{drift_detected: drifted, never_deployed: never, in_sync: in_sync}) do
    cond do
      drifted > 0 -> "#{drifted} drifted"
      never > 0 -> "#{never} never deployed"
      in_sync > 0 -> "#{in_sync} in sync"
      true -> "No sensors"
    end
  end

  def drift_summary_label(_summary), do: "No sensors"

  def drift_summary_status(%{drift_detected: drifted}) when drifted > 0, do: :drift_detected
  def drift_summary_status(%{never_deployed: never}) when never > 0, do: :never_deployed
  def drift_summary_status(%{in_sync: in_sync}) when in_sync > 0, do: :in_sync
  def drift_summary_status(_summary), do: :never_deployed

  def domains_label([]), do: Formatters.display(nil)
  def domains_label(nil), do: Formatters.display(nil)

  def domains_label(domains) when is_list(domains) do
    domains
    |> Enum.map(&status_label/1)
    |> Enum.join(", ")
  end

  def json_pretty(nil), do: "{}"

  def json_pretty(value) do
    case Jason.encode(value, pretty: true) do
      {:ok, json} -> json
      {:error, _reason} -> inspect(value, pretty: true)
    end
  end

  defp summary_part(summary, key, label) do
    count = Map.get(summary, key, Map.get(summary, to_string(key), 0))
    if count > 0, do: "#{count} #{label}"
  end

  defp to_datetime(%DateTime{} = datetime), do: datetime
  defp to_datetime(%NaiveDateTime{} = datetime), do: DateTime.from_naive!(datetime, "Etc/UTC")
end
