defmodule ConfigManager.Deployments.Deployment do
  @moduledoc "Tracked desired-state deployment for a sensor pool."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Deployments.DeploymentResult
  alias ConfigManager.SensorPool

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(pending validating deploying successful failed cancelled rolled_back)
  @operator_types ~w(user api_token system)
  @active_statuses ~w(pending validating deploying)
  @terminal_statuses ~w(successful failed cancelled rolled_back)
  @valid_transitions %{
    "pending" => ~w(validating cancelled),
    "validating" => ~w(deploying failed cancelled),
    "deploying" => ~w(successful failed cancelled),
    "successful" => ~w(rolled_back),
    "failed" => ~w(rolled_back),
    "cancelled" => [],
    "rolled_back" => []
  }

  schema "deployments" do
    field(:status, :string, default: "pending")
    field(:operator, :string)
    field(:operator_type, :string)
    field(:config_version, :integer)
    field(:forwarding_config_version, :integer)
    field(:bpf_version, :integer)
    field(:config_snapshot, :map)
    field(:diff_summary, :map)
    field(:started_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)
    field(:failure_reason, :string)

    belongs_to(:pool, SensorPool)
    belongs_to(:rollback_of_deployment, __MODULE__)
    belongs_to(:source_deployment, __MODULE__)
    has_many(:results, DeploymentResult)

    timestamps()
  end

  def statuses, do: @statuses
  def active_statuses, do: @active_statuses
  def terminal_statuses, do: @terminal_statuses
  def valid_transitions, do: @valid_transitions

  def create_changeset(deployment, attrs) do
    deployment
    |> cast(attrs, [
      :pool_id,
      :status,
      :operator,
      :operator_type,
      :config_version,
      :forwarding_config_version,
      :bpf_version,
      :config_snapshot,
      :diff_summary,
      :rollback_of_deployment_id,
      :source_deployment_id,
      :started_at,
      :completed_at,
      :failure_reason
    ])
    |> put_default_status()
    |> validate_required([
      :pool_id,
      :status,
      :operator,
      :operator_type,
      :config_version,
      :config_snapshot
    ])
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:operator_type, @operator_types)
    |> validate_number(:config_version, greater_than: 0)
    |> validate_map(:config_snapshot)
    |> foreign_key_constraint(:pool_id)
  end

  def status_changeset(deployment, status, attrs \\ %{}) do
    current_status = deployment.status

    deployment
    |> cast(Map.put(attrs, :status, status), [
      :status,
      :started_at,
      :completed_at,
      :failure_reason
    ])
    |> validate_required([:status])
    |> validate_inclusion(:status, @statuses)
    |> validate_transition(current_status)
  end

  defp put_default_status(changeset) do
    case get_field(changeset, :status) do
      nil -> put_change(changeset, :status, "pending")
      _status -> changeset
    end
  end

  defp validate_map(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_map(value), do: [], else: [{field, "must be a map"}]
    end)
  end

  defp validate_transition(changeset, nil), do: changeset

  defp validate_transition(changeset, current_status) do
    next_status = get_field(changeset, :status)

    cond do
      next_status == current_status ->
        changeset

      next_status in Map.get(@valid_transitions, current_status, []) ->
        changeset

      true ->
        add_error(
          changeset,
          :status,
          "invalid transition from #{current_status} to #{next_status}"
        )
    end
  end
end
