defmodule ConfigManager.Deployments.DeploymentResult do
  @moduledoc "Per-sensor result for a tracked deployment."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Deployments.Deployment
  alias ConfigManager.SensorPod

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @statuses ~w(pending pushing success failed unreachable skipped)
  @message_limit 2048

  schema "deployment_results" do
    field(:status, :string, default: "pending")
    field(:message, :string)
    field(:started_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)

    belongs_to(:deployment, Deployment)
    belongs_to(:sensor_pod, SensorPod)

    timestamps()
  end

  def statuses, do: @statuses
  def message_limit, do: @message_limit

  def create_changeset(result, attrs) do
    result
    |> cast(attrs, [:deployment_id, :sensor_pod_id, :status, :message, :started_at, :completed_at])
    |> put_default_status()
    |> truncate_message()
    |> validate_required([:deployment_id, :sensor_pod_id, :status])
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:deployment_id)
    |> foreign_key_constraint(:sensor_pod_id)
  end

  def update_changeset(result, attrs) do
    result
    |> cast(attrs, [:status, :message, :started_at, :completed_at])
    |> truncate_message()
    |> validate_inclusion(:status, @statuses)
  end

  defp put_default_status(changeset) do
    case get_field(changeset, :status) do
      nil -> put_change(changeset, :status, "pending")
      _status -> changeset
    end
  end

  defp truncate_message(changeset) do
    update_change(changeset, :message, fn
      nil -> nil
      message -> String.slice(to_string(message), 0, @message_limit)
    end)
  end
end
