defmodule ConfigManagerWeb.Api.RateLimiter do
  @moduledoc "ETS-backed per-token Public API rate limiter."

  use GenServer

  @table :config_manager_api_token_rate_limits
  @default_limit_per_minute 100
  @window_ms 60_000
  @prune_interval_ms 60_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def check(%{id: token_id}) when is_binary(token_id), do: check(token_id)

  def check(token_id) when is_binary(token_id) do
    with :ok <- ensure_table(@table) do
      limit = limit_per_minute()
      now = now_ms()

      case :ets.lookup(@table, token_id) do
        [{^token_id, count, first_seen_at}]
        when now - first_seen_at < @window_ms and count >= limit ->
          {:error, retry_after_seconds(now, first_seen_at), limit}

        [{^token_id, count, first_seen_at}] when now - first_seen_at < @window_ms ->
          :ets.insert(@table, {token_id, count + 1, first_seen_at})
          :ok

        _ ->
          :ets.insert(@table, {token_id, 1, now})
          :ok
      end
    end
  end

  def check(_token), do: {:error, :missing_token}

  def reset do
    if table_exists?(@table), do: :ets.delete_all_objects(@table)
    :ok
  end

  def prune_expired do
    now = now_ms()
    prune_table(@table, now)
    :ok
  end

  @impl true
  def init(_opts) do
    new_table(@table)
    schedule_prune()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:prune_expired, state) do
    prune_expired()
    schedule_prune()
    {:noreply, state}
  end

  defp retry_after_seconds(now, first_seen_at) do
    remaining_ms = max(@window_ms - (now - first_seen_at), 1)
    ceil(remaining_ms / 1000)
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

  defp limit_per_minute do
    :config_manager
    |> Application.get_env(:api_token_rate_limit_per_minute, @default_limit_per_minute)
    |> parse_positive_int(@default_limit_per_minute)
  end

  defp parse_positive_int(value, default) do
    case Integer.parse(to_string(value)) do
      {int, _} when int > 0 -> int
      _ -> default
    end
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
