defmodule ConfigManagerWeb.ConnCase do
  @moduledoc """
  Test case template for tests that need a Phoenix connection.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @endpoint ConfigManagerWeb.Endpoint

      use ConfigManagerWeb, :verified_routes
      import Plug.Conn
      import Phoenix.ConnTest
      import ConfigManagerWeb.ConnCase
    end
  end

  setup tags do
    ConfigManager.DataCase.setup_sandbox(tags)
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end
end
