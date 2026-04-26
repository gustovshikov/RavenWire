defmodule ConfigManager.DataCase do
  @moduledoc """
  Test case template for tests that interact with the database.
  Sets up the Ecto sandbox and provides helpers for test data.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      alias ConfigManager.Repo
      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import ConfigManager.DataCase
    end
  end

  setup tags do
    ConfigManager.DataCase.setup_sandbox(tags)
    :ok
  end

  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(ConfigManager.Repo, shared: not tags[:async])

    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end
end
