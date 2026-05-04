defmodule ConfigManagerWeb.FormattersTest do
  use ExUnit.Case, async: true

  alias ConfigManagerWeb.Formatters

  test "formats bytes with human-readable units" do
    assert Formatters.format_bytes(nil) == "—"
    assert Formatters.format_bytes(0) == "0 B"
    assert Formatters.format_bytes(1024) == "1.0 KB"
    assert Formatters.format_bytes(1_048_576) == "1.0 MB"
    assert Formatters.format_bytes(1_073_741_824) == "1.0 GB"
  end

  test "formats throughput and avoids negative rates" do
    assert Formatters.format_throughput(nil) == "—"
    assert Formatters.format_throughput(-1) == "0 bps"
    assert Formatters.format_throughput(999) == "999 bps"
    assert Formatters.format_throughput(1_000) == "1.0 Kbps"
    assert Formatters.format_throughput(1_000_000) == "1.0 Mbps"
  end

  test "formats uptime" do
    assert Formatters.format_uptime(nil) == "—"
    assert Formatters.format_uptime(0) == "0s"
    assert Formatters.format_uptime(59) == "59s"
    assert Formatters.format_uptime(3_600) == "1h 0m"
    assert Formatters.format_uptime(86_400) == "1d 0m"
  end

  test "classifies certificate expiration" do
    now = DateTime.utc_now()

    assert Formatters.cert_status(nil) == :unknown
    assert Formatters.cert_status(DateTime.add(now, -1, :day)) == :expired
    assert Formatters.cert_status(DateTime.add(now, 29, :day)) == :expiring_soon
    assert Formatters.cert_status(DateTime.add(now, 32, :day)) == :valid
  end

  test "formats utc timestamps and nil-safe values" do
    assert Formatters.display(nil) == "—"
    assert Formatters.display("") == "—"
    assert Formatters.display("ravenwire") == "ravenwire"

    assert Formatters.format_utc(~U[2026-05-03 12:30:45Z]) == "2026-05-03 12:30:45 UTC"
    assert Formatters.format_utc_from_unix_ms(1_767_182_400_000) =~ "UTC"
  end
end
