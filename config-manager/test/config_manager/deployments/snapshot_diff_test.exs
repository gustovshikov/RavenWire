defmodule ConfigManager.Deployments.SnapshotDiffTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Deployments.{Diff, Snapshot}
  alias ConfigManager.Pools

  test "snapshot captures all deployment domains and validates completeness" do
    {:ok, pool} =
      Pools.create_pool(
        %{
          "name" => "snapshot-pool",
          "pcap_ring_size_mb" => 8192,
          "alert_severity_threshold" => 1
        },
        "tester"
      )

    snapshot = Snapshot.capture(pool)

    assert :ok = Snapshot.validate(snapshot)
    assert snapshot["capture"]["version"] == pool.config_version
    assert snapshot["capture"]["pcap_ring_size_mb"] == 8192
    assert snapshot["forwarding"]["sinks"] == []
    assert snapshot["rules"]["files"] == %{}

    assert {:error, {:missing_domains, ["rules"]}} =
             snapshot
             |> Map.delete("rules")
             |> Snapshot.validate()
  end

  test "sink sanitization replaces secret material with presence indicators" do
    sanitized =
      Snapshot.sanitize_sink(%{
        "name" => "splunk",
        "uri" => "https://splunk.example",
        "token" => "secret-token",
        "auth" => %{"password" => "secret-password"}
      })

    assert sanitized["name"] == "splunk"
    assert sanitized["token_present"] == true
    assert sanitized["auth"]["password_present"] == true
    refute inspect(sanitized) =~ "secret-token"
    refute inspect(sanitized) =~ "secret-password"
  end

  test "diff reports changed capture, forwarding, bpf, and rule domains without secrets" do
    previous = %{
      "capture" => %{"version" => 1, "pcap_ring_size_mb" => 4096},
      "forwarding" => %{
        "version" => 1,
        "sinks" => [%{"name" => "splunk", "token" => "old-secret", "schema_mode" => "raw"}]
      },
      "bpf" => %{"version" => 1, "rules" => ["tcp port 80"]},
      "rules" => %{
        "version" => 1,
        "files" => %{"local.rules" => "alert tcp any any -> any any (sid:1;)"}
      }
    }

    current = %{
      "capture" => %{"version" => 2, "pcap_ring_size_mb" => 8192},
      "forwarding" => %{
        "version" => 2,
        "sinks" => [%{"name" => "splunk", "token" => "new-secret", "schema_mode" => "ecs"}]
      },
      "bpf" => %{"version" => 2, "rules" => ["tcp port 443"]},
      "rules" => %{
        "version" => 2,
        "files" => %{"local.rules" => "alert tcp any any -> any any (sid:2;)"}
      }
    }

    diff = Diff.compute(previous, current)

    assert diff["capture"]["pcap_ring_size_mb"] == %{"old" => 4096, "new" => 8192}
    assert diff["forwarding"]["sinks"]["modified"]["splunk"]["schema_mode"]
    assert diff["bpf"]["rules"]["added"] == ["tcp port 443"]
    assert diff["rules"]["files"]["modified"]["local.rules"]
    refute inspect(diff) =~ "old-secret"
    refute inspect(diff) =~ "new-secret"
  end
end
