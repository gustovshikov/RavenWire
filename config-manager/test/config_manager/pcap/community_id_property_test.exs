defmodule ConfigManager.Pcap.CommunityIdPropertyTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Pcap.CommunityId

  property "Community ID output is well formed and direction independent", [
    :verbose,
    numtests: 60
  ] do
    forall code <- integer(1, 50_000) do
      flow = flow_from_code(code)
      reverse = reverse_flow(flow)

      {:ok, community_id} = CommunityId.compute(flow)

      CommunityId.valid_format?(community_id) and
        CommunityId.compute(flow) == CommunityId.compute(reverse)
    end
  end

  property "Community ID format validation rejects malformed strings", [:verbose, numtests: 40] do
    forall code <- integer(1, 50_000) do
      invalid = "1:not-a-valid-community-id-#{code}"
      not CommunityId.valid_format?(invalid)
    end
  end

  defp flow_from_code(code) do
    %{
      "src_ip" => "192.0.2.#{rem(code, 200) + 1}",
      "dst_ip" => "198.51.100.#{rem(div(code, 200), 200) + 1}",
      "src_port" => rem(code, 65_535),
      "dst_port" => rem(div(code, 3), 65_535),
      "protocol" => Enum.at(["tcp", "udp"], rem(code, 2))
    }
  end

  defp reverse_flow(flow) do
    %{
      "src_ip" => flow["dst_ip"],
      "dst_ip" => flow["src_ip"],
      "src_port" => flow["dst_port"],
      "dst_port" => flow["src_port"],
      "protocol" => flow["protocol"]
    }
  end
end
