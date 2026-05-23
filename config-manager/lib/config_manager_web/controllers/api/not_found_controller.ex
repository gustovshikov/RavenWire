defmodule ConfigManagerWeb.Api.NotFoundController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  def not_found(conn, _params) do
    api_error(conn, :not_found, "NOT_FOUND", "Unsupported API route or version")
  end
end
