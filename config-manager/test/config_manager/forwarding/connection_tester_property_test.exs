defmodule ConfigManager.Forwarding.ConnectionTesterPropertyTest do
  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.Forwarding.{ConnectionTester, ForwardingSink}

  setup do
    {:ok, supervisor} = Task.Supervisor.start_link()
    on_exit(fn -> Process.exit(supervisor, :shutdown) end)
    {:ok, supervisor: supervisor}
  end

  property "Property 14: Connection test concurrency limiting",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 1_000) do
      max_concurrent = rem(code, 4) + 1
      supervisor = Process.get(:connection_tester_supervisor)
      sink = sink(code)

      tester = fn _sink, _opts ->
        Process.sleep(80)
        :ok
      end

      accepted =
        Enum.map(1..max_concurrent, fn _index ->
          ConnectionTester.test_async(sink, self(),
            supervisor: supervisor,
            max_concurrent: max_concurrent,
            tester: tester
          )
        end)

      excess =
        ConnectionTester.test_async(sink, self(),
          supervisor: supervisor,
          max_concurrent: max_concurrent,
          tester: tester
        )

      received_all? = receive_results(max_concurrent)

      Enum.all?(accepted, &(&1 == :ok)) and
        excess == {:error, :concurrent_limit} and
        received_all? and
        ConnectionTester.active_test_count(supervisor: supervisor) == 0
    end
  end

  setup %{supervisor: supervisor} do
    Process.put(:connection_tester_supervisor, supervisor)
    :ok
  end

  defp receive_results(count) do
    Enum.all?(1..count, fn _index ->
      receive do
        {:connection_test_result, _sink_id, %{success: true}} -> true
      after
        500 -> false
      end
    end)
  end

  defp sink(code) do
    %ForwardingSink{
      id: Ecto.UUID.generate(),
      name: "http-#{code}",
      normalized_name: "http-#{code}",
      sink_type: "http",
      config: Jason.encode!(%{"endpoint" => "https://8.8.8.8/collect", "method" => "POST"}),
      enabled: true
    }
  end
end
