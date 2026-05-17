defmodule ConfigManager.Deployments.Snapshot do
  @moduledoc "Captures a secret-safe desired-state snapshot for a sensor pool."

  alias ConfigManager.{Repo, SensorPool}

  @secret_keys ~w(token password secret api_key default_token private_key cert_pem ca_chain_pem)
  @required_domains ~w(capture bpf forwarding rules)

  def capture(%SensorPool{} = pool) do
    %{
      "captured_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "pool" => %{
        "id" => pool.id,
        "name" => pool.name,
        "config_version" => pool.config_version
      },
      "capture" => %{
        "version" => pool.config_version,
        "capture_mode" => pool.capture_mode,
        "pcap_ring_size_mb" => pool.pcap_ring_size_mb,
        "pre_alert_window_sec" => pool.pre_alert_window_sec,
        "post_alert_window_sec" => pool.post_alert_window_sec,
        "alert_severity_threshold" => pool.alert_severity_threshold
      },
      "bpf" => %{
        "version" => nil,
        "profile" => nil,
        "rules" => []
      },
      "forwarding" => %{
        "version" => 0,
        "sinks" => []
      },
      "rules" => %{
        "version" => 0,
        "files" => %{}
      }
    }
  end

  def capture(pool_id) when is_binary(pool_id) do
    pool_id
    |> Repo.get!(SensorPool)
    |> capture()
  end

  def validate(snapshot) when is_map(snapshot) do
    missing = Enum.reject(@required_domains, &Map.has_key?(snapshot, &1))

    cond do
      missing != [] ->
        {:error, {:missing_domains, missing}}

      not is_map(snapshot["capture"]) or is_nil(snapshot["capture"]["version"]) ->
        {:error, :invalid_capture_snapshot}

      not is_map(snapshot["forwarding"]) or not is_list(snapshot["forwarding"]["sinks"]) ->
        {:error, :invalid_forwarding_snapshot}

      not is_map(snapshot["rules"]) or not is_map(snapshot["rules"]["files"]) ->
        {:error, :invalid_rules_snapshot}

      true ->
        :ok
    end
  end

  def validate(_snapshot), do: {:error, :invalid_snapshot}

  def sanitize_sink(sink) when is_map(sink), do: sanitize_map(sink)
  def sanitize_sink(other), do: other

  defp sanitize_map(map) do
    Enum.reduce(map, %{}, fn {key, value}, acc ->
      key_string = to_string(key)

      if secret_key?(key_string) do
        Map.put(acc, "#{key_string}_present", present?(value))
      else
        Map.put(acc, key, sanitize_value(value))
      end
    end)
  end

  defp sanitize_value(value) when is_map(value), do: sanitize_map(value)
  defp sanitize_value(value) when is_list(value), do: Enum.map(value, &sanitize_value/1)
  defp sanitize_value(value), do: value

  defp secret_key?(key) do
    normalized = key |> String.downcase() |> String.replace("-", "_")
    normalized in @secret_keys or String.ends_with?(normalized, "_token")
  end

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(_value), do: true
end
