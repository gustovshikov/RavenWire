defmodule ConfigManager.Forwarding.DestinationValidator do
  @moduledoc """
  Validates forwarding connection-test destinations before network probes run.

  The validator rejects loopback, link-local, and private network destinations
  unless `ALLOW_PRIVATE_DESTINATIONS` is explicitly enabled for lab use.
  """

  import Bitwise

  @http_sink_types ~w(splunk_hec http)
  @truthy_env_values ~w(1 true yes on)

  def validate(destination, sink_type, opts \\ [])

  def validate(destination, sink_type, opts) when sink_type in @http_sink_types do
    destination
    |> parse_http_url()
    |> check_parsed_host(opts)
  end

  def validate(destination, "s3", opts) do
    if blank?(destination) do
      :ok
    else
      destination
      |> parse_http_url()
      |> check_parsed_host(opts)
    end
  end

  def validate(destination, "syslog", opts) do
    destination
    |> parse_host_port()
    |> check_parsed_host(opts)
  end

  def validate(destination, "kafka", opts) do
    destination
    |> to_string()
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> validate_bootstrap_servers(opts)
  end

  def validate(_destination, "file", _opts), do: :ok
  def validate(_destination, _sink_type, _opts), do: {:error, :unsupported_sink_type}

  def allow_private? do
    "ALLOW_PRIVATE_DESTINATIONS"
    |> System.get_env("false")
    |> String.downcase()
    |> then(&(&1 in @truthy_env_values))
  end

  def resolve_and_check(host), do: resolve_and_check(host, [])

  def resolve_and_check(host, opts) do
    with :ok <- validate_host_string(host),
         {:ok, addresses} <- resolve_host(host) do
      addresses
      |> Enum.map(&classify_address/1)
      |> Enum.find(:ok, &(&1 != :ok))
      |> maybe_allow_private(opts)
    end
  end

  def classify_address({127, _, _, _}), do: :loopback
  def classify_address({169, 254, _, _}), do: :link_local
  def classify_address({10, _, _, _}), do: :private_network
  def classify_address({172, second, _, _}) when second in 16..31, do: :private_network
  def classify_address({192, 168, _, _}), do: :private_network
  def classify_address({0, 0, 0, 0, 0, 0, 0, 1}), do: :loopback

  def classify_address({first, _, _, _, _, _, _, _}) when (first &&& 0xFFC0) == 0xFE80,
    do: :link_local

  def classify_address({first, _, _, _, _, _, _, _}) when (first &&& 0xFE00) == 0xFC00,
    do: :private_network

  def classify_address(_address), do: :ok

  defp validate_bootstrap_servers([], _opts), do: {:error, :malformed_host}

  defp validate_bootstrap_servers(servers, opts) do
    Enum.reduce_while(servers, :ok, fn server, :ok ->
      case server |> parse_host_port() |> check_parsed_host(opts) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp parse_http_url(destination) do
    if blank?(destination) do
      {:error, :malformed_url}
    else
      uri = URI.parse(to_string(destination))

      cond do
        uri.scheme not in ["http", "https"] and not is_nil(uri.scheme) ->
          {:error, :unsupported_scheme}

        uri.scheme not in ["http", "https"] or blank?(uri.host) ->
          {:error, :malformed_url}

        true ->
          {:ok, uri.host}
      end
    end
  end

  defp parse_host_port(%{} = destination) do
    host = value(destination, "host")
    port = value(destination, "port")

    with :ok <- validate_port(port) do
      {:ok, host}
    end
  end

  defp parse_host_port(destination) when is_binary(destination) do
    destination = String.trim(destination)

    cond do
      destination == "" ->
        {:error, :malformed_host}

      String.starts_with?(destination, "[") ->
        parse_bracketed_ipv6_port(destination)

      true ->
        parse_simple_host_port(destination)
    end
  end

  defp parse_host_port(_destination), do: {:error, :malformed_host}

  defp parse_bracketed_ipv6_port(destination) do
    case Regex.run(~r/^\[([^\]]+)\]:(\d+)$/, destination) do
      [_, host, port] ->
        with :ok <- validate_port(port), do: {:ok, host}

      _no_match ->
        {:error, :malformed_host}
    end
  end

  defp parse_simple_host_port(destination) do
    case String.split(destination, ":", parts: 2) do
      [host, port] ->
        with :ok <- validate_port(port), do: {:ok, host}

      _invalid ->
        {:error, :malformed_host}
    end
  end

  defp check_parsed_host({:ok, host}, opts), do: resolve_and_check(host, opts)
  defp check_parsed_host({:error, reason}, _opts), do: {:error, reason}

  defp resolve_host(host) do
    host = normalize_host(host)

    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} ->
        {:ok, [address]}

      {:error, :einval} ->
        resolve_hostname(host)
    end
  end

  defp resolve_hostname(host) do
    ipv4 = :inet.getaddrs(String.to_charlist(host), :inet)
    ipv6 = :inet.getaddrs(String.to_charlist(host), :inet6)

    addresses =
      [ipv4, ipv6]
      |> Enum.flat_map(fn
        {:ok, values} -> values
        _error -> []
      end)

    case addresses do
      [] -> {:error, :dns_resolution_failed}
      addresses -> {:ok, addresses}
    end
  end

  defp validate_host_string(host) do
    host = normalize_host(host)

    cond do
      blank?(host) ->
        {:error, :malformed_host}

      String.contains?(host, [" ", "/", "\\", "@"]) ->
        {:error, :malformed_host}

      true ->
        :ok
    end
  end

  defp validate_port(port) do
    case Integer.parse(to_string(port)) do
      {port, ""} when port in 1..65_535 -> :ok
      _invalid -> {:error, :invalid_port}
    end
  end

  defp maybe_allow_private(:ok, _opts), do: :ok

  defp maybe_allow_private(reason, opts)
       when reason in [:loopback, :link_local, :private_network] do
    if Keyword.get(opts, :allow_private?, allow_private?()) do
      :ok
    else
      {:error, reason}
    end
  end

  defp normalize_host(host) do
    host
    |> to_string()
    |> String.trim()
    |> String.trim_leading("[")
    |> String.trim_trailing("]")
  end

  defp value(map, key) do
    Map.get(map, key) || Map.get(map, String.to_atom(key))
  end

  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(nil), do: true
  defp blank?(_value), do: false
end
