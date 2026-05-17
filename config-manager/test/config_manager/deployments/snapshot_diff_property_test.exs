defmodule ConfigManager.Deployments.SnapshotDiffPropertyTest do
  @moduledoc "Property coverage for deployment snapshots, secret redaction, and diffs."

  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Deployments.{Diff, Snapshot}

  property "Property 1: configuration snapshots round-trip through JSON",
           [:verbose, numtests: 50] do
    forall code <- integer(1, 1_000) do
      snapshot = snapshot_from_code(code)

      Jason.decode!(Jason.encode!(snapshot)) == snapshot and
        Snapshot.validate(snapshot) == :ok
    end
  end

  property "Property 3: secret values are excluded from snapshots and diffs",
           [:verbose, numtests: 50] do
    forall code <- integer(1, 1_000) do
      old_secret = "old-secret-value-#{code}"
      new_secret = "new-secret-value-#{code}"

      previous =
        snapshot_from_code(code)
        |> put_in(["forwarding", "sinks"], [
          %{
            "name" => "splunk",
            "uri" => "https://splunk.example",
            "token" => old_secret,
            "auth" => %{"password" => old_secret}
          }
        ])

      current =
        snapshot_from_code(code + 1)
        |> put_in(["forwarding", "sinks"], [
          %{
            "name" => "splunk",
            "uri" => "https://splunk.example",
            "token" => new_secret,
            "auth" => %{"password" => new_secret}
          }
        ])

      sanitized = Snapshot.sanitize_sink(List.first(current["forwarding"]["sinks"]))
      diff = Diff.compute(previous, current)
      rendered = inspect(%{sanitized: sanitized, diff: diff})

      not String.contains?(rendered, old_secret) and
        not String.contains?(rendered, new_secret) and
        sanitized["token_present"] == true and
        sanitized["auth"]["password_present"] == true
    end
  end

  property "Property 10: diff computation identifies changes across all snapshot domains",
           [:verbose, numtests: 50] do
    forall code <- integer(1, 1_000) do
      previous = snapshot_from_code(code)
      current = changed_snapshot_from_code(code)
      diff = Diff.compute(previous, current)

      diff["capture"]["pcap_ring_size_mb"] == %{
        "old" => previous["capture"]["pcap_ring_size_mb"],
        "new" => current["capture"]["pcap_ring_size_mb"]
      } and
        diff["bpf"]["rules"]["added"] == ["tcp port #{code + 10}"] and
        diff["forwarding"]["sinks"]["modified"]["splunk"]["schema_mode"] == %{
          "old" => "raw",
          "new" => "ecs"
        } and
        diff["rules"]["files"]["modified"]["local.rules"] == %{
          "old" => previous["rules"]["files"]["local.rules"],
          "new" => current["rules"]["files"]["local.rules"]
        }
    end
  end

  defp snapshot_from_code(code) do
    version = rem(code, 50) + 1

    %{
      "captured_at" => "2026-05-17T00:00:00Z",
      "pool" => %{"id" => "pool-#{code}", "name" => "pool-#{code}", "config_version" => version},
      "capture" => %{
        "version" => version,
        "capture_mode" => "alert_driven",
        "pcap_ring_size_mb" => 1_024 + code,
        "pre_alert_window_sec" => rem(code, 90),
        "post_alert_window_sec" => rem(code, 60),
        "alert_severity_threshold" => rem(code, 3) + 1
      },
      "bpf" => %{
        "version" => version,
        "profile" => "default",
        "rules" => ["tcp port #{code}"]
      },
      "forwarding" => %{
        "version" => version,
        "sinks" => [
          %{
            "name" => "splunk",
            "uri" => "https://splunk.example",
            "schema_mode" => "raw"
          }
        ]
      },
      "rules" => %{
        "version" => version,
        "files" => %{"local.rules" => "alert tcp any any -> any any (sid:#{code};)"}
      }
    }
  end

  defp changed_snapshot_from_code(code) do
    code
    |> snapshot_from_code()
    |> put_in(["capture", "pcap_ring_size_mb"], 2_048 + code)
    |> put_in(["bpf", "rules"], ["tcp port #{code}", "tcp port #{code + 10}"])
    |> put_in(["forwarding", "sinks"], [
      %{
        "name" => "splunk",
        "uri" => "https://splunk.example",
        "schema_mode" => "ecs"
      }
    ])
    |> put_in(
      ["rules", "files", "local.rules"],
      "alert tcp any any -> any any (sid:#{code + 10};)"
    )
  end
end
