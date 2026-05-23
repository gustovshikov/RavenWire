defmodule ConfigManager.Pcap.CommunityIdTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Pcap.CommunityId

  @flow %{
    "src_ip" => "192.0.2.10",
    "dst_ip" => "198.51.100.22",
    "src_port" => "12345",
    "dst_port" => "443",
    "protocol" => "tcp"
  }

  test "computes a formatted version 1 SHA-256 Community ID" do
    assert {:ok, "1:" <> encoded = community_id} = CommunityId.compute(@flow)
    assert {:ok, decoded} = Base.decode64(encoded)
    assert byte_size(decoded) == 32
    assert CommunityId.valid_format?(community_id)
  end

  test "canonical ordering is direction independent" do
    reverse = %{
      "src_ip" => @flow["dst_ip"],
      "dst_ip" => @flow["src_ip"],
      "src_port" => @flow["dst_port"],
      "dst_port" => @flow["src_port"],
      "protocol" => "6"
    }

    assert CommunityId.compute(@flow) == CommunityId.compute(reverse)
  end

  test "supports IPv6 flows" do
    assert {:ok, community_id} =
             CommunityId.compute(%{
               src_ip: "2001:db8::1",
               dst_ip: "2001:db8::2",
               src_port: 5353,
               dst_port: 53,
               protocol: :udp
             })

    assert CommunityId.valid_format?(community_id)
  end

  test "validates format by decoding the hash length" do
    refute CommunityId.valid_format?("")
    refute CommunityId.valid_format?("2:abc")
    refute CommunityId.valid_format?("1:not-base64!")
    refute CommunityId.valid_format?("1:" <> Base.encode64("too-short"))
  end

  test "normalizes protocols and IP addresses" do
    assert {:ok, {127, 0, 0, 1}} = CommunityId.parse_ip("127.0.0.1")
    assert {:error, :invalid_ip} = CommunityId.parse_ip("999.0.0.1")
    assert {:ok, 6} = CommunityId.protocol_number("tcp")
    assert {:ok, 17} = CommunityId.protocol_number(:udp)
    assert {:ok, 1} = CommunityId.protocol_number("1")
    assert {:error, :invalid_protocol} = CommunityId.protocol_number("not-a-protocol")
  end
end
