defmodule ConfigManager.Forwarding.SinkConfigSchema do
  @moduledoc "Type-specific validation for forwarding sink configuration."

  @sink_types ~w(splunk_hec http syslog kafka s3 file)
  @sensitive_headers ~w(authorization cookie x-api-key x_api_key)

  @schema %{
    "splunk_hec" => %{
      required: ~w(endpoint),
      optional: ~w(index source_type tls_verify acknowledgements),
      secrets: ~w(hec_token)
    },
    "http" => %{
      required: ~w(endpoint method),
      optional: ~w(auth_type custom_headers tls_verify),
      secrets: ~w(bearer_token basic_username basic_password)
    },
    "syslog" => %{
      required: ~w(host port protocol format),
      optional: ~w(tls_enabled tls_verify),
      secrets: []
    },
    "kafka" => %{
      required: ~w(bootstrap_servers topic),
      optional: ~w(sasl_mechanism tls_enabled tls_verify compression),
      secrets: ~w(sasl_username sasl_password)
    },
    "s3" => %{
      required: ~w(bucket region),
      optional: ~w(endpoint prefix compression encoding),
      secrets: ~w(access_key_id secret_access_key)
    },
    "file" => %{
      required: ~w(path_template encoding),
      optional: [],
      secrets: []
    }
  }

  def validate(sink_type, attrs) do
    attrs = normalize_attrs(attrs)
    sink_type = normalize_key(sink_type)

    with :ok <- validate_sink_type(sink_type),
         :ok <- validate_required_fields(sink_type, attrs),
         :ok <- validate_type_specific(sink_type, attrs) do
      {:ok, sanitized_config(sink_type, attrs)}
    end
  end

  def sink_types, do: @sink_types

  def secret_fields(sink_type) do
    sink_type
    |> to_string()
    |> then(&get_in(@schema, [&1, :secrets]))
    |> Kernel.||([])
  end

  def required_fields(sink_type) do
    sink_type
    |> to_string()
    |> then(&get_in(@schema, [&1, :required]))
    |> Kernel.||([])
  end

  def required_secret_fields("splunk_hec", _attrs), do: ~w(hec_token)

  def required_secret_fields("http", attrs) do
    case normalize_value(value(normalize_attrs(attrs), "auth_type", "none")) do
      "bearer" -> ~w(bearer_token)
      "basic" -> ~w(basic_username basic_password)
      _other -> []
    end
  end

  def required_secret_fields("kafka", attrs) do
    case normalize_value(value(normalize_attrs(attrs), "sasl_mechanism", "none")) do
      "none" -> []
      _mechanism -> ~w(sasl_username sasl_password)
    end
  end

  def required_secret_fields("s3", _attrs), do: ~w(access_key_id secret_access_key)
  def required_secret_fields(_sink_type, _attrs), do: []

  def sensitive_headers, do: @sensitive_headers

  def contains_secret_field?(key) do
    normalized = normalize_key(key)

    Enum.any?(@schema, fn {_type, definition} ->
      normalized in definition.secrets
    end) or sensitive_header?(normalized)
  end

  def sensitive_header?(name) do
    name
    |> normalize_key()
    |> String.downcase()
    |> String.replace("-", "_")
    |> then(&(&1 in @sensitive_headers))
  end

  defp validate_sink_type(sink_type) when sink_type in @sink_types, do: :ok
  defp validate_sink_type(_sink_type), do: {:error, [sink_type: "is not supported"]}

  defp validate_required_fields(sink_type, attrs) do
    missing =
      sink_type
      |> required_fields()
      |> Enum.reject(&present?(value(attrs, &1)))

    case missing do
      [] -> :ok
      fields -> {:error, Enum.map(fields, &{String.to_atom(&1), "can't be blank"})}
    end
  end

  defp validate_type_specific("splunk_hec", attrs),
    do: validate_http_url(value(attrs, "endpoint"))

  defp validate_type_specific("http", attrs) do
    with :ok <- validate_http_url(value(attrs, "endpoint")),
         :ok <- validate_inclusion(attrs, "method", ~w(POST PUT)),
         :ok <- validate_inclusion(attrs, "auth_type", ~w(none bearer basic), default: "none") do
      :ok
    end
  end

  defp validate_type_specific("syslog", attrs) do
    with :ok <- validate_host(value(attrs, "host")),
         :ok <- validate_port(value(attrs, "port")),
         :ok <- validate_inclusion(attrs, "protocol", ~w(tcp udp)),
         :ok <- validate_inclusion(attrs, "format", ~w(rfc3164 rfc5424)) do
      :ok
    end
  end

  defp validate_type_specific("kafka", attrs) do
    with :ok <- validate_bootstrap_servers(value(attrs, "bootstrap_servers")),
         :ok <-
           validate_inclusion(attrs, "sasl_mechanism", ~w(none plain scram-sha-256 scram-sha-512),
             default: "none"
           ),
         :ok <-
           validate_inclusion(attrs, "compression", ~w(none gzip snappy lz4 zstd),
             default: "none"
           ) do
      :ok
    end
  end

  defp validate_type_specific("s3", attrs) do
    with :ok <- validate_simple_string(value(attrs, "bucket"), :bucket),
         :ok <- validate_simple_string(value(attrs, "region"), :region),
         :ok <- validate_optional_http_url(value(attrs, "endpoint")),
         :ok <- validate_inclusion(attrs, "compression", ~w(none gzip), default: "none"),
         :ok <- validate_inclusion(attrs, "encoding", ~w(json ndjson), default: "ndjson") do
      :ok
    end
  end

  defp validate_type_specific("file", attrs) do
    with :ok <- validate_file_path(value(attrs, "path_template")),
         :ok <- validate_inclusion(attrs, "encoding", ~w(json ndjson text)) do
      :ok
    end
  end

  defp sanitized_config(sink_type, attrs) do
    allowed_fields =
      sink_type
      |> fields_for_type()
      |> MapSet.new()

    attrs
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      normalized_key = normalize_key(key)

      cond do
        normalized_key == "custom_headers" and MapSet.member?(allowed_fields, normalized_key) ->
          Map.put(acc, normalized_key, sanitize_headers(value))

        MapSet.member?(allowed_fields, normalized_key) ->
          Map.put(acc, normalized_key, normalize_config_value(value))

        true ->
          acc
      end
    end)
    |> put_defaults(sink_type)
  end

  defp fields_for_type(sink_type) do
    definition = Map.fetch!(@schema, sink_type)
    definition.required ++ definition.optional
  end

  defp put_defaults(config, "http") do
    config
    |> Map.put_new("method", "POST")
    |> Map.update("method", "POST", &String.upcase(to_string(&1)))
    |> Map.put_new("auth_type", "none")
    |> Map.put_new("tls_verify", true)
  end

  defp put_defaults(config, "splunk_hec") do
    config
    |> Map.put_new("tls_verify", true)
    |> Map.put_new("acknowledgements", false)
  end

  defp put_defaults(config, "syslog") do
    config
    |> Map.put_new("protocol", "tcp")
    |> Map.put_new("format", "rfc5424")
    |> Map.put_new("tls_enabled", false)
    |> Map.put_new("tls_verify", true)
  end

  defp put_defaults(config, "kafka") do
    config
    |> Map.put_new("sasl_mechanism", "none")
    |> Map.put_new("tls_enabled", false)
    |> Map.put_new("tls_verify", true)
    |> Map.put_new("compression", "none")
  end

  defp put_defaults(config, "s3") do
    config
    |> Map.put_new("compression", "none")
    |> Map.put_new("encoding", "ndjson")
  end

  defp put_defaults(config, _sink_type), do: config

  defp sanitize_headers(headers) when is_map(headers) do
    Enum.reduce(headers, %{}, fn {name, value}, acc ->
      if sensitive_header?(name) do
        Map.put(acc, to_string(name), "[redacted]")
      else
        Map.put(acc, to_string(name), to_string(value))
      end
    end)
  end

  defp sanitize_headers(_headers), do: %{}

  defp validate_http_url(value) do
    with true <- present?(value),
         %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and not is_nil(host) <-
           URI.parse(to_string(value)) do
      :ok
    else
      _error -> {:error, [endpoint: "must be a valid http or https URL"]}
    end
  end

  defp validate_optional_http_url(value) do
    if present?(value), do: validate_http_url(value), else: :ok
  end

  defp validate_host(value) do
    if present?(value) and String.match?(to_string(value), ~r/^[a-zA-Z0-9._:-]+$/) do
      :ok
    else
      {:error, [host: "must be a valid host or IP address"]}
    end
  end

  defp validate_port(value) do
    case parse_integer(value) do
      port when port in 1..65_535 -> :ok
      _invalid -> {:error, [port: "must be between 1 and 65535"]}
    end
  end

  defp validate_bootstrap_servers(value) do
    servers =
      value
      |> to_string()
      |> String.split(",", trim: true)
      |> Enum.map(&String.trim/1)

    if servers != [] and Enum.all?(servers, &valid_host_port?/1) do
      :ok
    else
      {:error, [bootstrap_servers: "must contain host:port entries"]}
    end
  end

  defp valid_host_port?(server) do
    case String.split(server, ":", parts: 2) do
      [host, port] -> match?(:ok, validate_host(host)) and match?(:ok, validate_port(port))
      _invalid -> false
    end
  end

  defp validate_simple_string(value, field) do
    if present?(value), do: :ok, else: {:error, [{field, "can't be blank"}]}
  end

  defp validate_file_path(value) do
    if present?(value) and String.starts_with?(to_string(value), "/") do
      :ok
    else
      {:error, [path_template: "must be an absolute path"]}
    end
  end

  defp validate_inclusion(attrs, field, allowed, opts \\ []) do
    value =
      attrs
      |> value(field, Keyword.get(opts, :default))
      |> normalize_value()

    normalized_allowed = Enum.map(allowed, &normalize_value/1)

    if value in normalized_allowed do
      :ok
    else
      {:error, [{String.to_atom(field), "is not supported"}]}
    end
  end

  defp normalize_attrs(%{} = attrs) do
    attrs
    |> maybe_decode_config()
    |> Enum.reduce(%{}, fn {key, value}, acc -> Map.put(acc, normalize_key(key), value) end)
  end

  defp normalize_attrs(_attrs), do: %{}

  defp maybe_decode_config(attrs) do
    case Map.get(attrs, "config") || Map.get(attrs, :config) do
      config when is_map(config) ->
        Map.merge(attrs, config)

      config when is_binary(config) ->
        case Jason.decode(config) do
          {:ok, decoded} when is_map(decoded) -> Map.merge(attrs, decoded)
          _error -> attrs
        end

      _other ->
        attrs
    end
  end

  defp normalize_key(key) do
    key
    |> to_string()
    |> String.trim()
  end

  defp normalize_value(value) do
    value
    |> to_string()
    |> String.trim()
    |> String.downcase()
    |> String.replace("_", "-")
  end

  defp normalize_config_value(value) when is_binary(value), do: String.trim(value)
  defp normalize_config_value(value), do: value

  defp value(attrs, key, default \\ nil) do
    Map.get(attrs, key) || Map.get(attrs, to_string(key)) || default
  end

  defp parse_integer(value) when is_integer(value), do: value

  defp parse_integer(value) do
    case Integer.parse(to_string(value)) do
      {integer, ""} -> integer
      {integer, _rest} -> integer
      :error -> nil
    end
  end

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(nil), do: false
  defp present?(_value), do: true
end
