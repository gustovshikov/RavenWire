defmodule ConfigManager.Bpf.RuleParams do
  @moduledoc "Type-specific validation for structured BPF filter rule parameters."

  @valid_protocols ~w(any tcp udp)

  def validate("elephant_flow", params) when is_map(params) do
    params = normalize_params(params)

    with :ok <- validate_optional_cidr(params["src_cidr"]),
         :ok <- validate_optional_cidr(params["dst_cidr"]),
         :ok <- validate_optional_port_range(params["port"], params["port_end"]),
         :ok <- validate_protocol(params["protocol"]) do
      if present?(params["src_cidr"]) or present?(params["dst_cidr"]) or present?(params["port"]) do
        :ok
      else
        {:error, "requires at least one of src_cidr, dst_cidr, or port"}
      end
    end
  end

  def validate("cidr_pair", params) when is_map(params) do
    params = normalize_params(params)

    cond do
      not present?(params["src_cidr"]) ->
        {:error, "src_cidr is required"}

      not present?(params["dst_cidr"]) ->
        {:error, "dst_cidr is required"}

      true ->
        with :ok <- validate_cidr(params["src_cidr"]),
             :ok <- validate_cidr(params["dst_cidr"]) do
          :ok
        end
    end
  end

  def validate("port_exclusion", params) when is_map(params) do
    params = normalize_params(params)

    with :ok <- validate_required_port(params["port"]),
         :ok <- validate_optional_port_range(params["port"], params["port_end"]),
         :ok <- validate_protocol(params["protocol"]) do
      :ok
    end
  end

  def validate(_rule_type, params) when not is_map(params), do: {:error, "params must be a map"}
  def validate(_rule_type, _params), do: {:error, "unknown rule type"}

  def validate_cidr(cidr) when is_binary(cidr) do
    with [address, prefix] <- String.split(String.trim(cidr), "/", parts: 2),
         {prefix, ""} <- Integer.parse(prefix),
         {:ok, parsed_address} <- parse_address(address),
         true <- valid_prefix?(parsed_address, prefix) do
      :ok
    else
      _error -> {:error, "must be a valid IPv4 or IPv6 CIDR"}
    end
  end

  def validate_cidr(_cidr), do: {:error, "must be a valid IPv4 or IPv6 CIDR"}

  def validate_port(port) do
    case to_int(port) do
      port when is_integer(port) and port >= 1 and port <= 65_535 -> :ok
      _other -> {:error, "must be a port from 1 to 65535"}
    end
  end

  def validate_port_range(port_start, nil), do: validate_port(port_start)
  def validate_port_range(port_start, ""), do: validate_port(port_start)

  def validate_port_range(port_start, port_end) do
    with :ok <- validate_port(port_start),
         :ok <- validate_port(port_end),
         start_port <- to_int(port_start),
         end_port <- to_int(port_end),
         true <- start_port <= end_port do
      :ok
    else
      false -> {:error, "port_end must be greater than or equal to port"}
      {:error, _message} = error -> error
      _other -> {:error, "must be a valid port range"}
    end
  end

  def normalize_params(params) do
    params
    |> Enum.map(fn {key, value} -> {to_string(key), normalize_value(value)} end)
    |> Map.new()
    |> Map.update("protocol", "any", &normalize_protocol/1)
  end

  defp validate_required_port(port) do
    if present?(port), do: validate_port(port), else: {:error, "port is required"}
  end

  defp validate_optional_cidr(value) do
    if present?(value), do: validate_cidr(value), else: :ok
  end

  defp validate_optional_port_range(nil, nil), do: :ok
  defp validate_optional_port_range("", nil), do: :ok
  defp validate_optional_port_range(nil, ""), do: :ok
  defp validate_optional_port_range("", ""), do: :ok
  defp validate_optional_port_range(port, port_end), do: validate_port_range(port, port_end)

  defp validate_protocol(nil), do: :ok
  defp validate_protocol(""), do: :ok

  defp validate_protocol(protocol) do
    if normalize_protocol(protocol) in @valid_protocols do
      :ok
    else
      {:error, "protocol must be one of any, tcp, or udp"}
    end
  end

  defp parse_address(address) do
    address
    |> String.to_charlist()
    |> :inet.parse_address()
  end

  defp valid_prefix?({_, _, _, _}, prefix), do: prefix >= 0 and prefix <= 32
  defp valid_prefix?({_, _, _, _, _, _, _, _}, prefix), do: prefix >= 0 and prefix <= 128

  defp normalize_protocol(nil), do: "any"

  defp normalize_protocol(protocol),
    do: protocol |> to_string() |> String.trim() |> String.downcase()

  defp normalize_value(value) when is_binary(value), do: String.trim(value)
  defp normalize_value(value), do: value

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(value), do: not is_nil(value)

  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) when is_binary(value) do
    case Integer.parse(String.trim(value)) do
      {int, ""} -> int
      _other -> nil
    end
  end

  defp to_int(_value), do: nil
end
