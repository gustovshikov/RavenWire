defmodule ConfigManager.Pcap.SearchParamsPropertyTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Pcap.SearchParams

  property "time range validation accepts bounded forward ranges", [:verbose, numtests: 60] do
    forall seconds <- integer(1, 24 * 60 * 60) do
      start_time = ~U[2026-05-23 00:00:00Z]
      end_time = DateTime.add(start_time, seconds, :second)

      {:ok, params} =
        SearchParams.validate(%{
          "search_type" => "time_range",
          "start_time" => DateTime.to_iso8601(start_time),
          "end_time" => DateTime.to_iso8601(end_time)
        })

      payload = SearchParams.to_carve_payload(params, "request-id")

      payload.request_id == "request-id" and
        payload.search_type == "time_range" and
        payload.start_time == DateTime.to_iso8601(start_time) and
        payload.end_time == DateTime.to_iso8601(end_time)
    end
  end

  property "five tuple validation rejects out-of-range ports", [:verbose, numtests: 40] do
    forall port <- integer(65_536, 200_000) do
      {:error, errors} =
        SearchParams.validate(%{
          "search_type" => "five_tuple",
          "src_ip" => "192.0.2.10",
          "dst_ip" => "198.51.100.10",
          "src_port" => port,
          "dst_port" => 443,
          "protocol" => "tcp"
        })

      "must be between 0 and 65535" in errors["src_port"]
    end
  end
end
