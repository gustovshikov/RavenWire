defmodule ConfigManager.Forwarding.ConnectionTesterTest do
  use ExUnit.Case, async: false

  alias ConfigManager.Forwarding.{ConnectionTester, ForwardingSink}

  setup do
    {:ok, supervisor} = Task.Supervisor.start_link()
    on_exit(fn -> Process.exit(supervisor, :shutdown) end)
    {:ok, supervisor: supervisor}
  end

  test "HTTP sink connection tests return success for 2xx responses" do
    sink =
      sink("http", %{
        "endpoint" => "https://8.8.8.8/collect?token=secret",
        "method" => "POST"
      })

    result =
      ConnectionTester.test_sync(sink,
        requester: fn _request -> {:ok, %Finch.Response{status: 204, body: ""}} end
      )

    assert result.success
    assert result.message == "Connection successful"
    assert result.endpoint == "https://8.8.8.8/collect"
  end

  test "HTTP failures are categorized and endpoint details are sanitized" do
    sink =
      sink("http", %{
        "endpoint" => "https://user:pass@8.8.8.8/collect?api_key=secret",
        "method" => "POST"
      })

    auth_failure =
      ConnectionTester.test_sync(sink,
        requester: fn _request -> {:ok, %Finch.Response{status: 401, body: ""}} end
      )

    assert auth_failure.success == false
    assert auth_failure.error_category == "auth"
    assert auth_failure.endpoint == "https://8.8.8.8/collect"
    refute inspect(auth_failure) =~ "api_key=secret"
    refute inspect(auth_failure) =~ "user:pass"
  end

  test "blocked destinations fail before a network request is made" do
    sink = sink("http", %{"endpoint" => "https://127.0.0.1/collect", "method" => "POST"})

    result =
      ConnectionTester.test_sync(sink,
        requester: fn _request ->
          flunk("requester should not be called for blocked destinations")
        end
      )

    assert result.success == false
    assert result.error_category == "blocked"
    assert result.message =~ "loopback"
  end

  test "file sinks are not testable asynchronously" do
    assert {:error, :file_sink} =
             ConnectionTester.test_async(sink("file", %{}), self(), supervisor: self())
  end

  test "async tests send sanitized results back to the caller", %{supervisor: supervisor} do
    sink = sink("http", %{"endpoint" => "https://8.8.8.8/collect", "method" => "POST"})

    assert :ok =
             ConnectionTester.test_async(sink, self(),
               supervisor: supervisor,
               tester: fn _sink -> {:ok, %{success: true, message: "ok", error_category: nil}} end
             )

    assert_receive {:connection_test_result, sink_id, %{success: true, message: "ok"}}, 500
    assert sink_id == sink.id
  end

  test "sanitize_error_message redacts URL queries and credential-like fields" do
    message =
      "failed for https://example.test/path?token=secret Authorization=abc password=hunter2 Bearer abc"

    sanitized = ConnectionTester.sanitize_error_message(message)

    refute sanitized =~ "secret"
    refute sanitized =~ "hunter2"
    refute sanitized =~ "Bearer abc"
    assert sanitized =~ "?[redacted]"
    assert sanitized =~ "password=[redacted]"
    assert sanitized =~ "Bearer [redacted]"
  end

  defp sink(sink_type, config) do
    %ForwardingSink{
      id: Ecto.UUID.generate(),
      name: "#{sink_type}-sink",
      normalized_name: "#{sink_type}-sink",
      sink_type: sink_type,
      config: Jason.encode!(config),
      enabled: true
    }
  end
end
