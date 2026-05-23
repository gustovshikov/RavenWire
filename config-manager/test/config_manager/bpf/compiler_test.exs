defmodule ConfigManager.Bpf.CompilerTest do
  use ExUnit.Case, async: false

  alias ConfigManager.Bpf.Compiler

  test "empty expressions are valid and skip compilation" do
    assert {:ok, %{instruction_count: 0}} =
             Compiler.compile("", compiler: fn _expression -> flunk("should not compile") end)

    assert {:ok, %{instruction_count: 0, output: ""}} = Compiler.compile_sync(nil)
  end

  test "compile runs compiler asynchronously and normalizes success and failure" do
    assert {:ok, %{instruction_count: 3}} =
             Compiler.compile("tcp",
               compiler: fn "tcp" -> {:ok, %{instruction_count: 3, output: "x"}} end
             )

    assert {:error, %{message: "invalid syntax"}} =
             Compiler.compile("bad",
               compiler: fn "bad" -> {:error, %{message: "invalid syntax"}} end
             )
  end

  test "compile reports timeout" do
    assert {:error, %{message: "BPF compilation timed out"}} =
             Compiler.compile("tcp",
               timeout_ms: 5,
               compiler: fn _expression ->
                 Process.sleep(50)
                 {:ok, %{instruction_count: 1}}
               end
             )
  end
end
