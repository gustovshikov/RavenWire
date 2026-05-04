defmodule ConfigManagerWeb.Formatters do
  @moduledoc "Pure display formatting helpers shared by LiveViews."

  @dash "—"

  def format_bytes(nil), do: @dash
  def format_bytes(bytes) when not is_number(bytes), do: @dash
  def format_bytes(bytes) when bytes < 0, do: @dash
  def format_bytes(0), do: "0 B"

  def format_bytes(bytes) do
    cond do
      bytes >= 1_099_511_627_776 -> scaled(bytes, 1_099_511_627_776, "TB")
      bytes >= 1_073_741_824 -> scaled(bytes, 1_073_741_824, "GB")
      bytes >= 1_048_576 -> scaled(bytes, 1_048_576, "MB")
      bytes >= 1_024 -> scaled(bytes, 1_024, "KB")
      true -> "#{round(bytes)} B"
    end
  end

  def format_throughput(nil), do: @dash
  def format_throughput(bps) when not is_number(bps), do: @dash
  def format_throughput(bps) when bps < 0, do: "0 bps"

  def format_throughput(bps) do
    cond do
      bps >= 1_000_000_000 -> decimal(bps / 1_000_000_000) <> " Gbps"
      bps >= 1_000_000 -> decimal(bps / 1_000_000) <> " Mbps"
      bps >= 1_000 -> decimal(bps / 1_000) <> " Kbps"
      true -> "#{round(bps)} bps"
    end
  end

  def format_utc(nil), do: @dash

  def format_utc(%NaiveDateTime{} = datetime) do
    datetime
    |> DateTime.from_naive!("Etc/UTC")
    |> format_utc()
  end

  def format_utc(%DateTime{} = datetime) do
    datetime
    |> DateTime.shift_zone!("Etc/UTC")
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S UTC")
  end

  def format_utc(_), do: @dash

  def format_utc_from_unix_ms(nil), do: @dash

  def format_utc_from_unix_ms(unix_ms) when is_integer(unix_ms) and unix_ms > 0 do
    case DateTime.from_unix(unix_ms, :millisecond) do
      {:ok, datetime} -> format_utc(datetime)
      {:error, _reason} -> @dash
    end
  end

  def format_utc_from_unix_ms(_), do: @dash

  def format_relative_age(nil), do: @dash

  def format_relative_age(%NaiveDateTime{} = datetime) do
    datetime
    |> DateTime.from_naive!("Etc/UTC")
    |> format_relative_age()
  end

  def format_relative_age(%DateTime{} = datetime) do
    seconds = max(DateTime.diff(DateTime.utc_now(), datetime, :second), 0)

    cond do
      seconds < 60 -> plural(seconds, "second")
      seconds < 3_600 -> plural(div(seconds, 60), "minute")
      seconds < 86_400 -> plural(div(seconds, 3_600), "hour")
      true -> plural(div(seconds, 86_400), "day")
    end <> " ago"
  end

  def format_relative_age(_), do: @dash

  def cert_status(nil), do: :unknown

  def cert_status(%NaiveDateTime{} = datetime) do
    datetime |> DateTime.from_naive!("Etc/UTC") |> cert_status()
  end

  def cert_status(%DateTime{} = expires_at) do
    now = DateTime.utc_now()

    cond do
      DateTime.compare(expires_at, now) == :lt -> :expired
      DateTime.diff(expires_at, now, :day) <= 30 -> :expiring_soon
      true -> :valid
    end
  end

  def cert_status(_), do: :unknown

  def format_uptime(nil), do: @dash
  def format_uptime(seconds) when not is_integer(seconds), do: @dash
  def format_uptime(seconds) when seconds < 0, do: @dash
  def format_uptime(seconds) when seconds < 60, do: "#{seconds}s"

  def format_uptime(seconds) do
    days = div(seconds, 86_400)
    hours = seconds |> rem(86_400) |> div(3_600)
    minutes = seconds |> rem(3_600) |> div(60)

    [
      if(days > 0, do: "#{days}d"),
      if(hours > 0, do: "#{hours}h"),
      "#{minutes}m"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  def format_percent(value, decimals \\ 1)

  def format_percent(nil, decimals),
    do: :erlang.float_to_binary(0.0, decimals: decimals) <> "%"

  def format_percent(value, decimals) when is_number(value) do
    :erlang.float_to_binary(value / 1, decimals: decimals) <> "%"
  end

  def format_percent(_value, decimals), do: format_percent(nil, decimals)

  def display(nil), do: @dash
  def display(""), do: @dash
  def display(value), do: to_string(value)

  defp scaled(value, divisor, unit), do: decimal(value / divisor) <> " " <> unit
  defp decimal(value), do: :erlang.float_to_binary(value / 1, decimals: 1)

  defp plural(1, unit), do: "1 #{unit}"
  defp plural(count, unit), do: "#{count} #{unit}s"
end
