defmodule ConfigManager.Auth.RateLimiter do
  @moduledoc "ETS-backed login attempt rate limiter."

  use GenServer

  @username_table :config_manager_auth_username_failures
  @ip_table :config_manager_auth_ip_failures
  @window_ms 15 * 60 * 1000
  @default_username_limit 5
  @default_ip_limit 50
  @prune_interval_ms 60_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def check_username(username) do
    check(@username_table, username_key(username), username_limit())
  end

  def record_failure(username) do
    record(@username_table, username_key(username))
  end

  def clear_username(username) do
    delete(@username_table, username_key(username))
  end

  def check_ip(nil), do: :ok

  def check_ip(ip) do
    check(@ip_table, ip_key(ip), ip_limit())
  end

  def record_ip_failure(nil), do: :ok

  def record_ip_failure(ip) do
    record(@ip_table, ip_key(ip))
  end

  def clear_ip(nil), do: :ok

  def clear_ip(ip) do
    delete(@ip_table, ip_key(ip))
  end

  def prune_expired do
    now = now_ms()
    prune_table(@username_table, now)
    prune_table(@ip_table, now)
    :ok
  end

  def reset do
    if table_exists?(@username_table), do: :ets.delete_all_objects(@username_table)
    if table_exists?(@ip_table), do: :ets.delete_all_objects(@ip_table)
    :ok
  end

  @impl true
  def init(_opts) do
    new_table(@username_table)
    new_table(@ip_table)
    schedule_prune()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:prune_expired, state) do
    prune_expired()
    schedule_prune()
    {:noreply, state}
  end

  defp check(table, key, limit) do
    with :ok <- ensure_table(table) do
      now = now_ms()

      case :ets.lookup(table, key) do
        [{^key, count, first_seen_at}] when now - first_seen_at < @window_ms and count >= limit ->
          {:error, :rate_limited}

        [{^key, _count, first_seen_at}] when now - first_seen_at >= @window_ms ->
          :ets.delete(table, key)
          :ok

        _ ->
          :ok
      end
    end
  end

  defp record(table, key) do
    with :ok <- ensure_table(table) do
      now = now_ms()

      case :ets.lookup(table, key) do
        [{^key, count, first_seen_at}] when now - first_seen_at < @window_ms ->
          :ets.insert(table, {key, count + 1, first_seen_at})

        _ ->
          :ets.insert(table, {key, 1, now})
      end

      :ok
    end
  end

  defp delete(table, key) do
    with :ok <- ensure_table(table) do
      :ets.delete(table, key)
      :ok
    end
  end

  defp prune_table(table, now) do
    if table_exists?(table) do
      :ets.foldl(
        fn {key, _count, first_seen_at}, deleted ->
          if now - first_seen_at >= @window_ms do
            :ets.delete(table, key)
            deleted + 1
          else
            deleted
          end
        end,
        0,
        table
      )
    end
  end

  defp ensure_table(table) do
    if table_exists?(table), do: :ok, else: {:error, :unavailable}
  end

  defp table_exists?(table), do: :ets.info(table) != :undefined

  defp new_table(table) do
    :ets.new(table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])
  end

  defp schedule_prune do
    Process.send_after(self(), :prune_expired, @prune_interval_ms)
  end

  defp username_key(username) do
    username
    |> to_string()
    |> String.trim()
    |> String.downcase()
  end

  defp ip_key(ip) when is_tuple(ip) do
    ip
    |> Tuple.to_list()
    |> Enum.join(".")
  end

  defp ip_key(ip), do: to_string(ip)

  defp username_limit do
    "RAVENWIRE_LOGIN_USERNAME_FAILURE_LIMIT"
    |> System.get_env(to_string(@default_username_limit))
    |> parse_positive_int(@default_username_limit)
  end

  defp ip_limit do
    "RAVENWIRE_LOGIN_IP_FAILURE_LIMIT"
    |> System.get_env(to_string(@default_ip_limit))
    |> parse_positive_int(@default_ip_limit)
  end

  defp parse_positive_int(value, default) do
    case Integer.parse(to_string(value)) do
      {int, _} when int > 0 -> int
      _ -> default
    end
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
