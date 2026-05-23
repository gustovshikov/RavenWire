defmodule ConfigManagerWeb.Plugs.ApiVersionHeader do
  @moduledoc "Adds the current Public API version response header."

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    put_resp_header(conn, "x-api-version", "v1")
  end
end
