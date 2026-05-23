defmodule ConfigManager.Forwarding.ConnectionTester do
  @moduledoc "Bounded connection tests for configured forwarding sinks."

  alias ConfigManager.Forwarding.{DestinationValidator, Encryption, ForwardingSink, SinkSecret}
  alias ConfigManager.Repo

  import Ecto.Query

  @default_timeout_ms 10_000
  @default_max_concurrent_tests 5

  def test_async(sink, caller_pid, opts \\ [])

  def test_async(%ForwardingSink{sink_type: "file"}, _caller_pid, _opts),
    do: {:error, :file_sink}

  def test_async(%ForwardingSink{} = sink, caller_pid, opts) when is_pid(caller_pid) do
    supervisor = Keyword.get(opts, :supervisor, ConfigManager.Forwarding.TaskSupervisor)
    max_concurrent = Keyword.get(opts, :max_concurrent, @default_max_concurrent_tests)

    if active_test_count(supervisor: supervisor) >= max_concurrent do
      {:error, :concurrent_limit}
    else
      case Task.Supervisor.start_child(supervisor, fn ->
             result = test_sync(sink, opts)
             result = run_result_callback(sink, result, opts)
             send(caller_pid, {:connection_test_result, sink.id, result})
           end) do
        {:ok, _pid} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  end

  def test_sync(%ForwardingSink{} = sink, opts \\ []) do
    case Keyword.get(opts, :tester) do
      nil ->
        sink
        |> destination()
        |> validate_destination(sink, opts)
        |> run_test(sink, opts)

      tester ->
        call_tester(tester, sink, opts)
        |> normalize_result()
    end
  end

  def active_test_count(opts \\ []) do
    supervisor = Keyword.get(opts, :supervisor, ConfigManager.Forwarding.TaskSupervisor)

    supervisor
    |> Task.Supervisor.children()
    |> length()
  rescue
    _error -> 0
  end

  def sanitize_error_message(message) do
    message
    |> to_string()
    |> URI.decode()
    |> strip_url_query()
    |> String.replace(~r/(\bhttps?:\/\/)[^@\s\/]+@/i, "\\1")
    |> String.replace(
      ~r/(authorization|cookie|x-api-key|token|password|secret)=([^&\s]+)/i,
      "\\1=[redacted]"
    )
    |> String.replace(~r/(Splunk|Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]+/i, "\\1 [redacted]")
  end

  defp validate_destination({:error, reason}, _sink, _opts), do: {:error, reason}

  defp validate_destination({:ok, destination}, %ForwardingSink{} = sink, opts) do
    validator_opts = Keyword.take(opts, [:allow_private?])

    case DestinationValidator.validate(destination, sink.sink_type, validator_opts) do
      :ok -> {:ok, destination}
      {:error, reason} -> {:error, reason}
    end
  end

  defp run_test({:error, reason}, _sink, _opts), do: failure(reason)

  defp run_test({:ok, destination}, %ForwardingSink{sink_type: sink_type} = sink, opts)
       when sink_type in ["splunk_hec", "http", "s3"] do
    http_test(sink, destination, opts)
  end

  defp run_test({:ok, destination}, %ForwardingSink{sink_type: "syslog"} = sink, opts) do
    config = config_map(sink)

    tcp_test(
      destination,
      tls?: truthy?(Map.get(config, "tls_enabled")),
      tls_verify?: truthy?(Map.get(config, "tls_verify", true)),
      timeout_ms: timeout_ms(opts)
    )
  end

  defp run_test({:ok, destination}, %ForwardingSink{sink_type: "kafka"}, opts) do
    destination
    |> to_string()
    |> String.split(",", trim: true)
    |> List.first()
    |> tcp_test(tls?: false, tls_verify?: true, timeout_ms: timeout_ms(opts))
  end

  defp run_test(_destination, %ForwardingSink{sink_type: "file"}, _opts), do: {:error, :file_sink}
  defp run_test(_destination, _sink, _opts), do: failure(:unsupported_sink_type)

  defp http_test(%ForwardingSink{} = sink, destination, opts) do
    config = config_map(sink)
    requester = Keyword.get(opts, :requester, ConfigManager.Finch)
    method = http_method(sink, config)
    url = http_url(sink, destination)
    headers = http_headers(sink, config, opts)
    body = http_body(method)
    request = Finch.build(method, url, headers, body)

    case request(request, requester, sink, config, opts) do
      {:ok, %Finch.Response{status: status}} when status in 200..299 ->
        success("Connection successful", endpoint: sanitize_url(url))

      {:ok, %Finch.Response{status: status}} when status in [401, 403] ->
        failure(:auth, "Authentication rejected: HTTP #{status}", endpoint: sanitize_url(url))

      {:ok, %Finch.Response{status: status}} ->
        failure(:http, "Endpoint returned HTTP #{status}", endpoint: sanitize_url(url))

      {:error, reason} ->
        request_failure(reason, endpoint: sanitize_url(url))
    end
  end

  defp tcp_test(nil, _opts), do: failure(:malformed_host)

  defp tcp_test(destination, opts) do
    with {:ok, host, port} <- parse_host_port(destination) do
      timeout = Keyword.fetch!(opts, :timeout_ms)

      if Keyword.get(opts, :tls?, false) do
        tls_connect(host, port, opts, timeout)
      else
        tcp_connect(host, port, timeout)
      end
    else
      {:error, reason} -> failure(reason)
    end
  end

  defp tcp_connect(host, port, timeout) do
    case :gen_tcp.connect(String.to_charlist(host), port, [:binary, active: false], timeout) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        success("Connection successful", endpoint: "#{host}:#{port}")

      {:error, reason} ->
        request_failure(reason, endpoint: "#{host}:#{port}")
    end
  end

  defp tls_connect(host, port, opts, timeout) do
    ssl_opts =
      [
        server_name_indication: String.to_charlist(host),
        verify: if(Keyword.get(opts, :tls_verify?, true), do: :verify_peer, else: :verify_none),
        versions: [:"tlsv1.3", :"tlsv1.2"]
      ]

    case :ssl.connect(String.to_charlist(host), port, ssl_opts, timeout) do
      {:ok, socket} ->
        :ssl.close(socket)
        success("Connection successful", endpoint: "#{host}:#{port}")

      {:error, reason} ->
        request_failure(reason, endpoint: "#{host}:#{port}")
    end
  end

  defp request(request, requester, _sink, _config, _opts) when is_function(requester, 1),
    do: requester.(request)

  defp request(request, requester, sink, config, opts) when is_function(requester, 2),
    do: requester.(request, %{sink: sink, config: config, opts: opts})

  defp request(request, requester, _sink, config, opts) do
    Finch.request(request, requester,
      receive_timeout: timeout_ms(opts),
      pool_timeout: timeout_ms(opts),
      connect_options: connect_options(config)
    )
  end

  defp call_tester(tester, sink, _opts) when is_function(tester, 1), do: tester.(sink)
  defp call_tester(tester, sink, opts) when is_function(tester, 2), do: tester.(sink, opts)

  defp run_result_callback(sink, result, opts) do
    callback_result =
      case Keyword.get(opts, :on_result) do
        callback when is_function(callback, 2) ->
          callback.(sink, result)

        callback when is_function(callback, 3) ->
          callback.(sink, result, opts)

        _callback ->
          :ok
      end

    case callback_result do
      %{success: _success} = replacement -> replacement
      {:ok, %{success: _success} = replacement} -> replacement
      {:replace, %{success: _success} = replacement} -> replacement
      _other -> result
    end
  end

  defp destination(%ForwardingSink{sink_type: sink_type} = sink)
       when sink_type in ["splunk_hec", "http"] do
    {:ok, Map.get(config_map(sink), "endpoint")}
  end

  defp destination(%ForwardingSink{sink_type: "s3"} = sink) do
    config = config_map(sink)
    {:ok, Map.get(config, "endpoint") || s3_bucket_url(config)}
  end

  defp destination(%ForwardingSink{sink_type: "syslog"} = sink) do
    config = config_map(sink)
    {:ok, "#{Map.get(config, "host")}:#{Map.get(config, "port")}"}
  end

  defp destination(%ForwardingSink{sink_type: "kafka"} = sink) do
    {:ok, Map.get(config_map(sink), "bootstrap_servers")}
  end

  defp destination(%ForwardingSink{sink_type: "file"}), do: {:error, :file_sink}
  defp destination(_sink), do: {:error, :unsupported_sink_type}

  defp s3_bucket_url(%{"bucket" => bucket, "region" => region}) do
    "https://#{bucket}.s3.#{region}.amazonaws.com"
  end

  defp s3_bucket_url(_config), do: nil

  defp http_method(%ForwardingSink{sink_type: "s3"}, _config), do: :head
  defp http_method(%ForwardingSink{sink_type: "splunk_hec"}, _config), do: :get

  defp http_method(%ForwardingSink{sink_type: "http"}, config) do
    config
    |> Map.get("method", "POST")
    |> to_string()
    |> String.downcase()
    |> String.to_existing_atom()
  rescue
    ArgumentError -> :post
  end

  defp http_url(%ForwardingSink{sink_type: "splunk_hec"}, endpoint) do
    endpoint
    |> to_string()
    |> String.trim_trailing("/")
    |> Kernel.<>("/services/collector/health")
  end

  defp http_url(_sink, endpoint), do: endpoint

  defp http_headers(%ForwardingSink{sink_type: "splunk_hec"} = sink, _config, opts) do
    case secret_map(sink, opts) do
      %{"hec_token" => token} when token != "" -> [{"authorization", "Splunk #{token}"}]
      _secrets -> []
    end
  end

  defp http_headers(%ForwardingSink{sink_type: "http"} = sink, config, opts) do
    headers =
      config
      |> Map.get("custom_headers", %{})
      |> Enum.reject(fn {key, value} -> value == "[redacted]" or blank?(key) end)
      |> Enum.map(fn {key, value} -> {to_string(key), to_string(value)} end)

    case {Map.get(config, "auth_type", "none"), secret_map(sink, opts)} do
      {"bearer", %{"bearer_token" => token}} when token != "" ->
        [{"authorization", "Bearer #{token}"} | headers]

      {"basic", %{"basic_username" => username, "basic_password" => password}} ->
        credential = Base.encode64("#{username}:#{password}")
        [{"authorization", "Basic #{credential}"} | headers]

      _other ->
        headers
    end
  end

  defp http_headers(_sink, _config, _opts), do: []

  defp http_body(:get), do: nil
  defp http_body(:head), do: nil
  defp http_body(_method), do: "{}"

  defp connect_options(config) do
    if truthy?(Map.get(config, "tls_verify", true)) do
      []
    else
      [transport_opts: [verify: :verify_none]]
    end
  end

  defp secret_map(%ForwardingSink{} = sink, opts) do
    case Keyword.fetch(opts, :secrets) do
      {:ok, secrets} ->
        secrets

      :error ->
        SinkSecret
        |> where([s], s.forwarding_sink_id == ^sink.id)
        |> Repo.all()
        |> Enum.reduce(%{}, fn secret, acc ->
          case Encryption.decrypt(secret.ciphertext) do
            {:ok, plaintext} -> Map.put(acc, secret.secret_name, plaintext)
            {:error, _reason} -> acc
          end
        end)
    end
  rescue
    _error -> %{}
  end

  defp config_map(%ForwardingSink{config: config}) when is_binary(config) do
    case Jason.decode(config) do
      {:ok, decoded} when is_map(decoded) -> decoded
      _error -> %{}
    end
  end

  defp config_map(_sink), do: %{}

  defp parse_host_port(destination) do
    destination = to_string(destination)

    case String.split(destination, ":", parts: 2) do
      [host, port] ->
        case Integer.parse(port) do
          {port, ""} when port in 1..65_535 -> {:ok, host, port}
          _invalid -> {:error, :invalid_port}
        end

      _invalid ->
        {:error, :malformed_host}
    end
  end

  defp timeout_ms(opts), do: Keyword.get(opts, :timeout_ms, @default_timeout_ms)

  defp success(message, extra \\ []) do
    Map.merge(
      %{success: true, message: message, error_category: nil},
      Map.new(extra)
    )
  end

  defp failure(reason, message \\ nil, extra \\ []) do
    category = error_category(reason)

    Map.merge(
      %{
        success: false,
        message: message || default_error_message(reason),
        error_category: category
      },
      Map.new(extra)
    )
  end

  defp request_failure(reason, extra) do
    reason
    |> error_reason()
    |> then(fn normalized -> failure(normalized, default_error_message(normalized), extra) end)
  end

  defp normalize_result(%{success: _success} = result), do: result
  defp normalize_result({:ok, %{success: _success} = result}), do: result
  defp normalize_result(:ok), do: success("Connection successful")
  defp normalize_result({:ok, _value}), do: success("Connection successful")
  defp normalize_result({:error, reason}), do: failure(reason)
  defp normalize_result(other), do: failure(:unknown, inspect(other))

  defp error_reason(:timeout), do: :timeout
  defp error_reason(:nxdomain), do: :dns
  defp error_reason(:econnrefused), do: :connection
  defp error_reason(:closed), do: :connection
  defp error_reason(%Mint.TransportError{reason: :timeout}), do: :timeout
  defp error_reason(%Mint.TransportError{reason: reason}), do: reason
  defp error_reason(%Mint.HTTPError{reason: reason}), do: reason
  defp error_reason(reason), do: reason

  defp error_category(:auth), do: "auth"
  defp error_category(:timeout), do: "timeout"
  defp error_category(:dns), do: "dns"
  defp error_category(:nxdomain), do: "dns"
  defp error_category(:econnrefused), do: "connection"
  defp error_category(:connection), do: "connection"
  defp error_category(:http), do: "http"
  defp error_category(:tls), do: "tls"
  defp error_category(:file_sink), do: "unsupported"

  defp error_category(reason) when reason in [:loopback, :link_local, :private_network],
    do: "blocked"

  defp error_category(reason)
       when reason in [:malformed_url, :malformed_host, :invalid_port, :unsupported_scheme],
       do: "validation"

  defp error_category(_reason), do: "connection"

  defp default_error_message(:timeout), do: "Endpoint unreachable within timeout"
  defp default_error_message(:dns), do: "DNS resolution failed for host"
  defp default_error_message(:nxdomain), do: "DNS resolution failed for host"
  defp default_error_message(:econnrefused), do: "Connection refused by endpoint"
  defp default_error_message(:connection), do: "Connection failed"
  defp default_error_message(:loopback), do: "Destination is blocked: loopback address"
  defp default_error_message(:link_local), do: "Destination is blocked: link-local address"

  defp default_error_message(:private_network),
    do: "Destination is blocked: private network address"

  defp default_error_message(:file_sink), do: "File sinks do not have a remote endpoint to test"
  defp default_error_message(:malformed_url), do: "Destination URL is malformed"
  defp default_error_message(:malformed_host), do: "Destination host is malformed"
  defp default_error_message(:invalid_port), do: "Destination port is invalid"
  defp default_error_message(:unsupported_scheme), do: "Destination URL scheme is not supported"

  defp default_error_message(reason),
    do: "Connection failed: #{sanitize_error_message(inspect(reason))}"

  defp sanitize_url(value) do
    uri = value |> to_string() |> URI.parse()

    %URI{uri | userinfo: nil, query: nil, fragment: nil}
    |> URI.to_string()
  end

  defp strip_url_query(message) do
    String.replace(message, ~r/(\bhttps?:\/\/[^\s?]+)\?[^\s]+/, "\\1?[redacted]")
  end

  defp truthy?(value) when value in [true, "true", "1", 1, "on"], do: true
  defp truthy?(value) when value in [false, "false", "0", 0, "off", nil], do: false
  defp truthy?(_value), do: false

  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(nil), do: true
  defp blank?(_value), do: false
end
