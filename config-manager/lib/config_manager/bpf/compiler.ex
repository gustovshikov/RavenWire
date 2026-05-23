defmodule ConfigManager.Bpf.Compiler do
  @moduledoc "Server-side BPF expression compilation using tcpdump."

  @default_timeout_ms 5_000

  def compile(expression, opts \\ []) do
    expression = normalize_expression(expression)

    if expression == "" do
      {:ok, %{instruction_count: 0}}
    else
      timeout = Keyword.get(opts, :timeout_ms, @default_timeout_ms)
      compiler = Keyword.get(opts, :compiler, &compile_sync/1)

      task =
        Task.Supervisor.async_nolink(ConfigManager.Bpf.TaskSupervisor, fn ->
          compiler.(expression)
        end)

      case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
        {:ok, result} -> normalize_result(result)
        nil -> {:error, %{message: "BPF compilation timed out"}}
      end
    end
  end

  def compile_sync(expression) do
    expression = normalize_expression(expression)

    if expression == "" do
      {:ok, %{instruction_count: 0, output: ""}}
    else
      case System.cmd("tcpdump", ["-d", expression], stderr_to_stdout: true) do
        {output, 0} ->
          {:ok, %{instruction_count: instruction_count(output), output: output}}

        {output, _status} ->
          {:error, %{message: sanitize_output(output)}}
      end
    end
  rescue
    error in ErlangError ->
      {:error, %{message: format_system_error(error)}}
  end

  defp normalize_result({:ok, %{instruction_count: count}}) do
    {:ok, %{instruction_count: count}}
  end

  defp normalize_result({:error, %{message: message}}), do: {:error, %{message: message}}

  defp normalize_result({:error, message}) when is_binary(message),
    do: {:error, %{message: message}}

  defp normalize_result(other), do: {:error, %{message: inspect(other)}}

  defp instruction_count(output) do
    output
    |> String.split("\n", trim: true)
    |> length()
  end

  defp sanitize_output(output) do
    output
    |> to_string()
    |> String.trim()
    |> case do
      "" -> "BPF compilation failed"
      message -> message
    end
  end

  defp format_system_error(%ErlangError{original: :enoent}),
    do: "BPF compiler is not available. Install tcpdump."

  defp format_system_error(error), do: Exception.message(error)

  defp normalize_expression(nil), do: ""
  defp normalize_expression(expression), do: expression |> to_string() |> String.trim()
end
