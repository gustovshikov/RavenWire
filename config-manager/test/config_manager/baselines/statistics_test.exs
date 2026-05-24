defmodule ConfigManager.Baselines.StatisticsTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Baselines.Statistics

  test "compute_profile calculates distribution fields from finite values" do
    assert {:ok, profile} = Statistics.compute_profile([1, 2, 3, 4, "bad"], 4)

    assert profile.mean == 2.5
    assert_in_delta profile.stddev, 1.118, 0.001
    assert profile.p5 == 1.15
    assert_in_delta profile.p95, 3.85, 0.001
    assert profile.min_value == 1.0
    assert profile.max_value == 4.0
    assert profile.sample_count == 4
  end

  test "classification handles normal values, sigma anomalies, and flat baselines" do
    baseline = %{mean: 50.0, stddev: 5.0, p5: 40.0, p95: 60.0}

    assert Statistics.classify(52.0, baseline, 3.0) == :normal
    assert {:anomaly, score} = Statistics.classify(70.0, baseline, 3.0)
    assert score == 4.0

    assert Statistics.classify(50.0, %{baseline | stddev: 0.0, p5: 50.0, p95: 50.0}) == :normal

    assert {:anomaly, _score} =
             Statistics.classify(55.0, %{baseline | stddev: 0.0, p5: 50.0, p95: 50.0})
  end

  test "linear regression projects capacity trends and estimates threshold breach" do
    points = [{1, 10}, {2, 20}, {3, 30}, {4, 40}]

    assert {:ok, regression} = Statistics.linear_regression(points, 4)
    assert_in_delta regression.slope, 10.0, 0.001
    assert_in_delta Statistics.project(regression, 5), 50.0, 0.001
    assert {:ok, breach_at} = Statistics.time_to_threshold(regression, 45.0, 4, 10)
    assert_in_delta breach_at, 4.5, 0.001
  end

  property "anomaly score is symmetric around the baseline mean", [:verbose, numtests: 80] do
    forall {mean, stddev, delta} <- {integer(1, 1_000), integer(1, 200), integer(0, 500)} do
      high = Statistics.anomaly_score(mean + delta, mean, stddev)
      low = Statistics.anomaly_score(mean - delta, mean, stddev)
      abs(high - low) < 0.000001
    end
  end
end
