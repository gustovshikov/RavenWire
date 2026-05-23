defmodule ConfigManager.Pcap.CommunityId do
  @moduledoc """
  Community ID v1 calculation and validation helpers for PCAP search.

  The implementation follows the project PCAP spec: canonicalize the
  direction-independent 5-tuple, hash the packed tuple with SHA-256, and encode
  the result as `1:<base64>`.
  """

  @type flow :: %{
          optional(:src_ip) => String.t(),
          optional(:dst_ip) => String.t(),
          optional(:src_port) => integer() | String.t(),
          optional(:dst_port) => integer() | String.t(),
          optional(:protocol) => integer() | String.t() | atom()
        }

  @protocol_numbers %{
    "icmp" => 1,
    "tcp" => 6,
    "udp" => 17,
    "icmpv6" => 58,
    "ipv6-icmp" => 58
  }

  @doc "Computes a Community ID from a 5-tuple map."
  @spec compute(flow(), non_neg_integer()) :: {:ok, String.t()} | {:error, term()}
  def compute(flow, seed \\ 0)

  def compute(flow, seed) when is_map(flow) and is_integer(seed) and seed in 0..65_535 do
    with {:ok, src_ip} <- fetch_ip(flow, "src_ip"),
         {:ok, dst_ip} <- fetch_ip(flow, "dst_ip"),
         {:ok, src_port} <- fetch_port(flow, "src_port"),
         {:ok, dst_port} <- fetch_port(flow, "dst_port"),
         {:ok, protocol} <- fetch_protocol(flow) do
      {src_ip, src_port, dst_ip, dst_port} = canonical_order(src_ip, src_port, dst_ip, dst_port)

      packed =
        <<
          seed::16,
          pack_ip(src_ip)::binary,
          pack_ip(dst_ip)::binary,
          protocol::8,
          0::8,
          src_port::16,
          dst_port::16
        >>

      {:ok, "1:" <> (:crypto.hash(:sha256, packed) |> Base.encode64())}
    end
  end

  def compute(_flow, _seed), do: {:error, :invalid_seed}

  @doc "Computes a Community ID and raises when the supplied 5-tuple is invalid."
  @spec compute!(flow(), non_neg_integer()) :: String.t()
  def compute!(flow, seed \\ 0) do
    case compute(flow, seed) do
      {:ok, community_id} -> community_id
      {:error, reason} -> raise ArgumentError, "invalid Community ID flow: #{inspect(reason)}"
    end
  end

  @doc "Returns true when a value is a version-1 Community ID with a 32-byte hash."
  @spec valid_format?(term()) :: boolean()
  def valid_format?("1:" <> encoded) when byte_size(encoded) > 0 do
    with {:ok, decoded} <- decode_hash(encoded) do
      byte_size(decoded) == 32
    else
      :error -> false
    end
  end

  def valid_format?(_value), do: false

  @doc "Parses an IPv4 or IPv6 string."
  @spec parse_ip(term()) :: {:ok, :inet.ip_address()} | {:error, :invalid_ip}
  def parse_ip(value) when is_binary(value) do
    case value |> String.trim() |> to_charlist() |> :inet.parse_address() do
      {:ok, ip} -> {:ok, ip}
      {:error, _reason} -> {:error, :invalid_ip}
    end
  end

  def parse_ip(_value), do: {:error, :invalid_ip}

  @doc "Normalizes a protocol name or number to its IP protocol number."
  @spec protocol_number(term()) :: {:ok, 0..255} | {:error, :invalid_protocol}
  def protocol_number(value) when is_integer(value) and value in 0..255, do: {:ok, value}

  def protocol_number(value) when is_atom(value),
    do: value |> Atom.to_string() |> protocol_number()

  def protocol_number(value) when is_binary(value) do
    normalized = value |> String.trim() |> String.downcase()

    cond do
      Map.has_key?(@protocol_numbers, normalized) ->
        {:ok, Map.fetch!(@protocol_numbers, normalized)}

      Regex.match?(~r/^\d+$/, normalized) ->
        case Integer.parse(normalized) do
          {number, ""} when number in 0..255 -> {:ok, number}
          _other -> {:error, :invalid_protocol}
        end

      true ->
        {:error, :invalid_protocol}
    end
  end

  def protocol_number(_value), do: {:error, :invalid_protocol}

  defp fetch_ip(flow, key) do
    flow
    |> value(key)
    |> parse_ip()
    |> case do
      {:ok, ip} -> {:ok, ip}
      {:error, _reason} -> {:error, {key, :invalid_ip}}
    end
  end

  defp fetch_port(flow, key) do
    case normalize_port(value(flow, key)) do
      port when is_integer(port) and port in 0..65_535 -> {:ok, port}
      _other -> {:error, {key, :invalid_port}}
    end
  end

  defp fetch_protocol(flow) do
    case protocol_number(value(flow, "protocol")) do
      {:ok, protocol} -> {:ok, protocol}
      {:error, _reason} -> {:error, {"protocol", :invalid_protocol}}
    end
  end

  defp value(map, key), do: Map.get(map, key) || Map.get(map, String.to_atom(key))

  defp normalize_port(value) when is_integer(value), do: value

  defp normalize_port(value) when is_binary(value) do
    case Integer.parse(String.trim(value)) do
      {port, ""} -> port
      _other -> nil
    end
  end

  defp normalize_port(_value), do: nil

  defp canonical_order(src_ip, src_port, dst_ip, dst_port) do
    src_key = {ip_order_key(src_ip), src_port}
    dst_key = {ip_order_key(dst_ip), dst_port}

    if src_key <= dst_key do
      {src_ip, src_port, dst_ip, dst_port}
    else
      {dst_ip, dst_port, src_ip, src_port}
    end
  end

  defp ip_order_key(ip) do
    packed = pack_ip(ip)
    {byte_size(packed), :binary.decode_unsigned(packed)}
  end

  defp pack_ip({a, b, c, d}), do: <<a, b, c, d>>

  defp pack_ip({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  defp decode_hash(encoded) do
    case Base.decode64(encoded) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> Base.url_decode64(encoded)
    end
  end
end
