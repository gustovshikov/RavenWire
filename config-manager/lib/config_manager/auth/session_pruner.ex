defmodule ConfigManager.Auth.SessionPruner do
  @moduledoc "Periodically removes expired browser sessions."

  use GenServer

  require Logger

  alias ConfigManager.Auth

  @default_interval_ms :timer.minutes(15)

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    state = %{interval_ms: interval_ms(opts)}
    schedule_prune(state.interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_info(:prune_expired_sessions, state) do
    prune_expired_sessions()
    schedule_prune(state.interval_ms)
    {:noreply, state}
  end

  defp prune_expired_sessions do
    Auth.prune_expired_sessions()
  rescue
    exception ->
      Logger.warning("Session pruning failed: #{Exception.message(exception)}")
  end

  defp schedule_prune(interval_ms) do
    Process.send_after(self(), :prune_expired_sessions, interval_ms)
  end

  defp interval_ms(opts) do
    opts
    |> Keyword.get(:interval_ms, configured_interval_ms())
    |> parse_positive_int(@default_interval_ms)
  end

  defp configured_interval_ms do
    Application.get_env(:config_manager, :session_prune_interval_ms) ||
      System.get_env("RAVENWIRE_SESSION_PRUNE_INTERVAL_MS") ||
      @default_interval_ms
  end

  defp parse_positive_int(value, default) do
    case Integer.parse(to_string(value)) do
      {int, _} when int > 0 -> int
      _ -> default
    end
  end
end
