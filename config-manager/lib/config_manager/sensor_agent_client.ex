defmodule ConfigManager.SensorAgentClient do
  @moduledoc """
  HTTP client for dispatching control commands to Sensor_Agent instances via mTLS.

  Config_Manager does NOT access the Podman socket directly; all lifecycle
  operations are mediated through the Sensor_Agent's narrow control API.

  Requirements: 10.6, 10.7, 11.2, 11.3
  """

  require Logger

  @control_port 9091
  @timeout_ms 10_000

  @doc "Validates the active Sensor Agent configuration."
  @spec validate_config(map()) :: {:ok, map()} | {:error, term()}
  def validate_config(pod), do: post_control(pod, "/control/config/validate", "validate_config")

  @doc "Reloads Zeek through the Sensor Agent control API."
  @spec reload_zeek(map()) :: {:ok, map()} | {:error, term()}
  def reload_zeek(pod), do: post_control(pod, "/control/reload/zeek", "reload_zeek")

  @doc "Reloads Suricata through the Sensor Agent control API."
  @spec reload_suricata(map()) :: {:ok, map()} | {:error, term()}
  def reload_suricata(pod), do: post_control(pod, "/control/reload/suricata", "reload_suricata")

  @doc "Restarts Vector through the Sensor Agent control API."
  @spec restart_vector(map()) :: {:ok, map()} | {:error, term()}
  def restart_vector(pod), do: post_control(pod, "/control/restart/vector", "restart_vector")

  @doc """
  POSTs a `switch-capture-mode` command to the Sensor_Agent on the given pod.

  Sends Alert-Driven PCAP configuration to `POST /control/capture-mode`.

  Returns `{:ok, response_body}` on HTTP 2xx, or `{:error, reason}`.
  """
  @spec switch_capture_mode(map(), map()) :: {:ok, map()} | {:error, term()}
  def switch_capture_mode(%{control_api_host: nil}, _config),
    do: {:error, :no_control_api_host}

  def switch_capture_mode(%{control_api_host: ""}, _config),
    do: {:error, :no_control_api_host}

  def switch_capture_mode(pod, config) do
    url = "https://#{pod.control_api_host}:#{@control_port}/control/capture-mode"

    body =
      Jason.encode!(%{
        mode: "alert_driven",
        ring_size_mb: config.pcap_ring_size_mb,
        pre_alert_window_sec: config.pre_alert_window_sec,
        post_alert_window_sec: config.post_alert_window_sec,
        alert_severity_threshold: config.alert_severity_threshold
      })

    headers = [{"content-type", "application/json"}]

    request = Finch.build(:post, url, headers, body)

    case Finch.request(request, ConfigManager.Finch,
           receive_timeout: @timeout_ms,
           connect_options: mtls_opts()
         ) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        Logger.info("switch_capture_mode succeeded for pod #{pod.name} (HTTP #{status})")
        {:ok, decode_body(resp_body)}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.warning(
          "switch_capture_mode failed for pod #{pod.name}: HTTP #{status} — #{resp_body}"
        )

        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        Logger.warning(
          "switch_capture_mode request error for pod #{pod.name}: #{inspect(reason)}"
        )

        {:error, reason}
    end
  end

  @doc """
  Packages Suricata rules into a bundle and POSTs to `POST /control/config` on the
  target Sensor_Agent.

  `rules` is a map of `%{filename => rule_content}` (e.g. `%{"local.rules" => "alert ..."}`).
  `opts` may include `:version` (integer) and `:updated_by` (string).

  The bundle is sent as a JSON payload with `type: "suricata_rules"` and a
  `config` map of filename → content.  The Sensor_Agent Config Applier writes
  the files atomically to `/etc/suricata/rules/` and sends SIGUSR2 to Suricata.

  Returns `{:ok, response_body}` on HTTP 2xx, or `{:error, reason}`.

  Requirements: 7.3, 7.4
  """
  @spec push_rule_bundle(map(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def push_rule_bundle(pod, rules, opts \\ [])

  def push_rule_bundle(%{control_api_host: nil}, _rules, _opts),
    do: {:error, :no_control_api_host}

  def push_rule_bundle(%{control_api_host: ""}, _rules, _opts),
    do: {:error, :no_control_api_host}

  def push_rule_bundle(pod, rules, opts) when is_map(rules) do
    url = "https://#{pod.control_api_host}:#{@control_port}/control/config"

    version = Keyword.get(opts, :version, 1)
    updated_by = Keyword.get(opts, :updated_by, "config-manager")

    body =
      Jason.encode!(%{
        type: "suricata_rules",
        config: rules,
        version: version,
        updated_by: updated_by
      })

    headers = [{"content-type", "application/json"}]
    request = Finch.build(:post, url, headers, body)

    case Finch.request(request, ConfigManager.Finch,
           receive_timeout: @timeout_ms,
           connect_options: mtls_opts()
         ) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        Logger.info("push_rule_bundle succeeded for pod #{pod.name} (HTTP #{status})")
        {:ok, decode_body(resp_body)}

      {:ok, %Finch.Response{status: 422, body: resp_body}} ->
        Logger.warning("push_rule_bundle validation error for pod #{pod.name}: #{resp_body}")
        {:error, {:validation_error, decode_body(resp_body)}}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.warning(
          "push_rule_bundle failed for pod #{pod.name}: HTTP #{status} — #{resp_body}"
        )

        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        Logger.warning("push_rule_bundle request error for pod #{pod.name}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  POSTs to `POST /control/support-bundle` on the Sensor_Agent to trigger bundle generation.

  Returns `{:ok, %{"bundle_path" => path}}` on success, or `{:error, reason}`.

  Requirements: 25.4
  """
  @spec request_support_bundle(map()) :: {:ok, map()} | {:error, term()}
  def request_support_bundle(%{control_api_host: nil}), do: {:error, :no_control_api_host}
  def request_support_bundle(%{control_api_host: ""}), do: {:error, :no_control_api_host}

  def request_support_bundle(pod) do
    url = "https://#{pod.control_api_host}:#{@control_port}/control/support-bundle"
    headers = [{"content-type", "application/json"}]
    request = Finch.build(:post, url, headers, "{}")

    case Finch.request(request, ConfigManager.Finch,
           receive_timeout: @timeout_ms,
           connect_options: mtls_opts()
         ) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        Logger.info("request_support_bundle succeeded for pod #{pod.name} (HTTP #{status})")
        {:ok, decode_body(resp_body)}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.warning(
          "request_support_bundle failed for pod #{pod.name}: HTTP #{status} — #{resp_body}"
        )

        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        Logger.warning(
          "request_support_bundle request error for pod #{pod.name}: #{inspect(reason)}"
        )

        {:error, reason}
    end
  end

  @doc """
  GETs the support bundle archive from the Sensor_Agent.

  `path` is the bundle path returned by `request_support_bundle/1`.

  Returns `{:ok, binary_data}` or `{:error, reason}`.

  Requirements: 25.4
  """
  @bundle_timeout_ms 60_000

  @spec download_support_bundle(map(), String.t()) :: {:ok, binary()} | {:error, term()}
  def download_support_bundle(%{control_api_host: nil}, _path), do: {:error, :no_control_api_host}
  def download_support_bundle(%{control_api_host: ""}, _path), do: {:error, :no_control_api_host}

  def download_support_bundle(pod, path) do
    encoded_path = URI.encode_www_form(path)

    url =
      "https://#{pod.control_api_host}:#{@control_port}/control/support-bundle/download?path=#{encoded_path}"

    request = Finch.build(:get, url, [], nil)

    case Finch.request(request, ConfigManager.Finch,
           receive_timeout: @bundle_timeout_ms,
           connect_options: mtls_opts()
         ) do
      {:ok, %Finch.Response{status: status, body: body}} when status in 200..299 ->
        Logger.info(
          "download_support_bundle succeeded for pod #{pod.name} (#{byte_size(body)} bytes)"
        )

        {:ok, body}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.warning(
          "download_support_bundle failed for pod #{pod.name}: HTTP #{status} — #{resp_body}"
        )

        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        Logger.warning(
          "download_support_bundle request error for pod #{pod.name}: #{inspect(reason)}"
        )

        {:error, reason}
    end
  end

  # ── Private ──────────────────────────────────────────────────────────────────

  defp post_control(%{control_api_host: nil}, _path, _action), do: {:error, :no_control_api_host}
  defp post_control(%{control_api_host: ""}, _path, _action), do: {:error, :no_control_api_host}

  defp post_control(pod, path, action) do
    url = "https://#{pod.control_api_host}:#{@control_port}#{path}"
    headers = [{"content-type", "application/json"}]
    request = Finch.build(:post, url, headers, "{}")

    case Finch.request(request, ConfigManager.Finch,
           receive_timeout: @timeout_ms,
           connect_options: mtls_opts()
         ) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        Logger.info("#{action} succeeded for pod #{pod.name} (HTTP #{status})")
        {:ok, decode_body(resp_body)}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.warning("#{action} failed for pod #{pod.name}: HTTP #{status} — #{resp_body}")
        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        Logger.warning("#{action} request error for pod #{pod.name}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp mtls_opts do
    cert_path = Application.get_env(:config_manager, :mtls_cert_path)
    key_path = Application.get_env(:config_manager, :mtls_key_path)
    ca_path = Application.get_env(:config_manager, :ca_path, "/etc/sensor/certs")

    ssl_opts =
      [
        verify: :verify_peer,
        versions: [:"tlsv1.3", :"tlsv1.2"],
        cacertfile: Path.join(ca_path, "intermediate-ca.cert.pem")
      ]
      |> maybe_add_cert(cert_path)
      |> maybe_add_key(key_path)

    [transport_opts: ssl_opts]
  end

  defp maybe_add_cert(opts, nil), do: opts
  defp maybe_add_cert(opts, ""), do: opts
  defp maybe_add_cert(opts, path), do: Keyword.put(opts, :certfile, path)

  defp maybe_add_key(opts, nil), do: opts
  defp maybe_add_key(opts, ""), do: opts
  defp maybe_add_key(opts, path), do: Keyword.put(opts, :keyfile, path)

  defp decode_body(""), do: %{}

  defp decode_body(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> decoded
      {:error, _} -> %{raw: body}
    end
  end
end
