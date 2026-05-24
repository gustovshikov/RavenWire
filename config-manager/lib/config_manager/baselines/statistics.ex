defmodule ConfigManager.Baselines.Statistics do
  @moduledoc "Pure statistical helpers for health baselines and capacity forecasts."

  @epsilon 1.0e-9
  @zero_stddev_score 1.0e12

  def compute_profile(values, min_samples \\ 240) do
    values = values |> Enum.filter(&finite_number?/1) |> Enum.map(&(&1 / 1))

    if length(values) < min_samples do
      {:error, :insufficient_data}
    else
      sorted = Enum.sort(values)
      count = length(sorted)
      mean = Enum.sum(sorted) / count
      variance = sorted |> Enum.map(&:math.pow(&1 - mean, 2)) |> Enum.sum() |> Kernel./(count)

      {:ok,
       %{
         mean: mean,
         stddev: :math.sqrt(variance),
         p5: percentile(sorted, 5),
         p95: percentile(sorted, 95),
         min_value: List.first(sorted),
         max_value: List.last(sorted),
         sample_count: count
       }}
    end
  end

  def percentile([], _percent), do: nil

  def percentile([value], _percent) when is_number(value), do: value / 1

  def percentile(values, percent) when is_list(values) and is_number(percent) do
    sorted = Enum.sort(values)
    rank = max(min(percent, 100), 0) / 100 * (length(sorted) - 1)
    lower_index = rank |> :math.floor() |> trunc()
    upper_index = rank |> :math.ceil() |> trunc()
    lower = Enum.at(sorted, lower_index)
    upper = Enum.at(sorted, upper_index)

    if lower_index == upper_index do
      lower / 1
    else
      lower + (upper - lower) * (rank - lower_index)
    end
  end

  def anomaly_score(value, mean, stddev, min_delta \\ 0.0) do
    diff = abs(value - mean)

    cond do
      diff <= @epsilon ->
        0.0

      stddev > 0 ->
        diff / stddev

      diff > min_delta ->
        @zero_stddev_score

      true ->
        0.0
    end
  end

  def classify(value, baseline, sigma_threshold \\ 3.0, min_delta \\ 0.0) do
    mean = numeric(baseline, :mean)
    stddev = numeric(baseline, :stddev)
    p5 = numeric(baseline, :p5)
    p95 = numeric(baseline, :p95)
    score = anomaly_score(value, mean, stddev, min_delta)

    anomalous? =
      if stddev <= 0 do
        score > 0.0
      else
        score > sigma_threshold or value < p5 or value > p95
      end

    if anomalous?, do: {:anomaly, score}, else: :normal
  end

  def linear_regression(points, min_points \\ 12) do
    points =
      points
      |> Enum.map(fn {x, y} -> {x / 1, y / 1} end)
      |> Enum.filter(fn {x, y} -> finite_number?(x) and finite_number?(y) end)

    if length(points) < min_points do
      {:error, :insufficient_data}
    else
      count = length(points)
      mean_x = points |> Enum.map(&elem(&1, 0)) |> Enum.sum() |> Kernel./(count)
      mean_y = points |> Enum.map(&elem(&1, 1)) |> Enum.sum() |> Kernel./(count)

      numerator =
        points
        |> Enum.map(fn {x, y} -> (x - mean_x) * (y - mean_y) end)
        |> Enum.sum()

      denominator =
        points
        |> Enum.map(fn {x, _y} -> :math.pow(x - mean_x, 2) end)
        |> Enum.sum()

      if abs(denominator) <= @epsilon do
        {:error, :flat_trend}
      else
        slope = numerator / denominator
        intercept = mean_y - slope * mean_x
        predicted = Enum.map(points, fn {x, _y} -> slope * x + intercept end)

        ss_res =
          points
          |> Enum.zip(predicted)
          |> Enum.map(fn {{_x, y}, pred} -> :math.pow(y - pred, 2) end)
          |> Enum.sum()

        ss_tot = points |> Enum.map(fn {_x, y} -> :math.pow(y - mean_y, 2) end) |> Enum.sum()
        r_squared = if ss_tot <= @epsilon, do: 1.0, else: max(0.0, 1.0 - ss_res / ss_tot)

        {:ok, %{slope: slope, intercept: intercept, r_squared: r_squared}}
      end
    end
  end

  def project(%{slope: slope, intercept: intercept}, future_timestamp) do
    slope * future_timestamp + intercept
  end

  def project(slope, intercept, future_timestamp) do
    slope * future_timestamp + intercept
  end

  def time_to_threshold(
        %{slope: slope, intercept: intercept},
        threshold,
        now_timestamp,
        horizon_seconds
      ) do
    cond do
      abs(slope) <= @epsilon ->
        {:error, :flat_trend}

      true ->
        breach_at = (threshold - intercept) / slope
        horizon_end = now_timestamp + horizon_seconds
        current = project(slope, intercept, now_timestamp)

        if breach_at >= now_timestamp and breach_at <= horizon_end and
             threshold_crossed?(current, threshold, slope) do
          {:ok, breach_at}
        else
          {:error, :no_breach}
        end
    end
  end

  defp threshold_crossed?(current, threshold, slope) when slope > 0, do: current < threshold
  defp threshold_crossed?(current, threshold, slope) when slope < 0, do: current > threshold

  defp numeric(map, key) when is_map(map) do
    (Map.get(map, key) || Map.get(map, to_string(key)) || 0) / 1
  end

  defp finite_number?(value) when is_integer(value), do: true

  defp finite_number?(value) when is_float(value) do
    value == value and value > -1.0e308 and value < 1.0e308
  end

  defp finite_number?(_value), do: false
end
