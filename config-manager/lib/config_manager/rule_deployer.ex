defmodule ConfigManager.RuleDeployer do
  @moduledoc """
  Packages Suricata rules from the Rule_Store and delivers them to Sensor_Agents
  via `POST /control/config` (apply-pool-config action).

  The deployer:
    1. Accepts a map of `%{filename => rule_content}` representing the ruleset.
    2. POSTs the bundle to each enrolled pod in the target pool via mTLS.
    3. Returns a per-pod result map.

  Requirements: 7.3, 7.4
  """

  require Logger

  alias ConfigManager.{Repo, SensorAgentClient, SensorPod}
  import Ecto.Query

  @doc """
  Deploys a Suricata rule bundle to all enrolled pods in the given pool.

  `pool_id` — the UUID of the target Sensor_Pool.
  `rules`   — map of `%{filename => rule_content}`, e.g.:
                `%{"local.rules" => "alert tcp any any -> any any (msg:\\"test\\"; sid:1;)\\n"}`
  `opts`    — keyword list:
                `:version`    — integer config version (default 1)
                `:updated_by` — operator identity string (default "config-manager")

  Returns `{:ok, results}` where `results` is a list of
  `%{pod_id: id, pod_name: name, result: {:ok, _} | {:error, _}}`.
  """
  @spec deploy_to_pool(binary(), map(), keyword()) :: {:ok, list(map())}
  def deploy_to_pool(pool_id, rules, opts \\ []) when is_map(rules) do
    pods =
      Repo.all(
        from p in SensorPod,
          where: p.pool_id == ^pool_id and p.status == "enrolled",
          select: p
      )

    results =
      Enum.map(pods, fn pod ->
        result = SensorAgentClient.push_rule_bundle(pod, rules, opts)

        case result do
          {:ok, _} ->
            Logger.info("RuleDeployer: deployed rules to pod #{pod.name} (pool #{pool_id})")

          {:error, reason} ->
            Logger.warning(
              "RuleDeployer: failed to deploy rules to pod #{pod.name}: #{inspect(reason)}"
            )
        end

        %{pod_id: pod.id, pod_name: pod.name, result: result}
      end)

    {:ok, results}
  end

  @doc """
  Deploys a Suricata rule bundle to a single pod by pod ID.

  Returns `{:ok, response}` or `{:error, reason}`.
  """
  @spec deploy_to_pod(binary(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def deploy_to_pod(pod_id, rules, opts \\ []) when is_map(rules) do
    case Repo.get(SensorPod, pod_id) do
      nil ->
        {:error, :pod_not_found}

      pod ->
        SensorAgentClient.push_rule_bundle(pod, rules, opts)
    end
  end
end
