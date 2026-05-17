defmodule ConfigManager.Auth.RateLimiterTest do
  use ExUnit.Case, async: false

  alias ConfigManager.Auth.RateLimiter

  setup do
    previous_ip_limit = System.get_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT")
    RateLimiter.reset()

    on_exit(fn ->
      RateLimiter.reset()
      restore_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT", previous_ip_limit)
    end)

    :ok
  end

  test "username limiter rejects attempts after the configured failure threshold" do
    assert :ok = RateLimiter.check_username(" Operator ")

    for _attempt <- 1..5 do
      assert :ok = RateLimiter.record_failure("operator")
    end

    assert {:error, :rate_limited} = RateLimiter.check_username("OPERATOR")
    assert :ok = RateLimiter.clear_username("operator")
    assert :ok = RateLimiter.check_username("operator")
  end

  test "ip limiter uses the configured threshold" do
    System.put_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT", "2")

    assert :ok = RateLimiter.check_ip({127, 0, 0, 1})
    assert :ok = RateLimiter.record_ip_failure("127.0.0.1")
    assert :ok = RateLimiter.record_ip_failure({127, 0, 0, 1})

    assert {:error, :rate_limited} = RateLimiter.check_ip("127.0.0.1")
    assert :ok = RateLimiter.clear_ip({127, 0, 0, 1})
    assert :ok = RateLimiter.check_ip("127.0.0.1")
  end

  test "prune_expired removes stale limiter entries and keeps active entries" do
    stale_seen_at = System.monotonic_time(:millisecond) - :timer.minutes(16)
    fresh_seen_at = System.monotonic_time(:millisecond)

    :ets.insert(:config_manager_auth_username_failures, {"stale-user", 5, stale_seen_at})
    :ets.insert(:config_manager_auth_username_failures, {"fresh-user", 3, fresh_seen_at})
    :ets.insert(:config_manager_auth_ip_failures, {"192.0.2.10", 50, stale_seen_at})
    :ets.insert(:config_manager_auth_ip_failures, {"192.0.2.11", 1, fresh_seen_at})

    assert :ok = RateLimiter.prune_expired()

    assert [] = :ets.lookup(:config_manager_auth_username_failures, "stale-user")
    assert [{"fresh-user", 3, ^fresh_seen_at}] = :ets.lookup(:config_manager_auth_username_failures, "fresh-user")
    assert [] = :ets.lookup(:config_manager_auth_ip_failures, "192.0.2.10")
    assert [{"192.0.2.11", 1, ^fresh_seen_at}] = :ets.lookup(:config_manager_auth_ip_failures, "192.0.2.11")
  end

  defp restore_env(key, nil), do: System.delete_env(key)
  defp restore_env(key, value), do: System.put_env(key, value)
end
