defmodule ConfigManager.Pcap.SearchParamsTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Pcap.{CommunityId, SearchParams}

  test "validates Community ID searches and builds carve payloads" do
    community_id =
      CommunityId.compute!(%{
        src_ip: "192.0.2.1",
        dst_ip: "198.51.100.1",
        src_port: 1234,
        dst_port: 443,
        protocol: "tcp"
      })

    assert {:ok, params} =
             SearchParams.validate(%{
               "search_type" => "community_id",
               "community_id" => community_id,
               "start_time" => "2026-05-23T10:00",
               "end_time" => "2026-05-23T10:05",
               "sensor_pod_ids" => ["sensor-a", ""]
             })

    assert params.search_type == "community_id"
    assert params.sensor_pod_ids == ["sensor-a"]

    assert SearchParams.to_carve_payload(params, "request-1") == %{
             request_id: "request-1",
             search_type: "community_id",
             params: %{
               "community_id" => community_id,
               "start_time" => "2026-05-23T10:00",
               "end_time" => "2026-05-23T10:05"
             },
             start_time: "2026-05-23T10:00",
             end_time: "2026-05-23T10:05"
           }
  end

  test "validates all supported search types" do
    assert {:ok, _params} =
             SearchParams.validate(%{
               "search_type" => "time_range",
               "start_time" => "2026-05-23T10:00:00Z",
               "end_time" => "2026-05-23T11:00:00Z"
             })

    assert {:ok, _params} =
             SearchParams.validate(%{
               "search_type" => "five_tuple",
               "src_ip" => "192.0.2.1",
               "dst_ip" => "198.51.100.1",
               "src_port" => "0",
               "dst_port" => "65535",
               "protocol" => "udp"
             })

    assert {:ok, _params} = SearchParams.validate(%{"search_type" => "alert_id", "sid" => "1"})

    assert {:ok, _params} =
             SearchParams.validate(%{"search_type" => "zeek_uid", "zeek_uid" => "C1"})
  end

  test "returns field errors for invalid params" do
    assert {:error, errors} =
             SearchParams.validate(%{
               "search_type" => "five_tuple",
               "src_ip" => "bad",
               "dst_ip" => "198.51.100.1",
               "src_port" => "65536",
               "dst_port" => "53",
               "protocol" => "bad"
             })

    assert "is invalid" in errors["src_ip"]
    assert "must be between 0 and 65535" in errors["src_port"]
    assert "is invalid" in errors["protocol"]
  end

  test "rejects reversed and oversized time ranges" do
    assert {:error, errors} =
             SearchParams.validate(%{
               "search_type" => "time_range",
               "start_time" => "2026-05-23T11:00:00Z",
               "end_time" => "2026-05-23T10:00:00Z"
             })

    assert "must be after start_time" in errors["end_time"]

    assert {:error, errors} =
             SearchParams.validate(%{
               "search_type" => "time_range",
               "start_time" => "2026-05-22T10:00:00Z",
               "end_time" => "2026-05-23T10:00:01Z"
             })

    assert "range exceeds 24 hours" in errors["end_time"]
  end
end
