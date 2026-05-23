defmodule ConfigManagerWeb.Plugs.ApiRateLimit do
  @moduledoc "Applies per-token Public API rate limiting."

  import Plug.Conn
  import Phoenix.Controller

  alias ConfigManagerWeb.Api.{Errors, RateLimiter}

  def init(opts), do: opts

  def call(conn, _opts) do
    case RateLimiter.check(conn.assigns[:current_token]) do
      :ok ->
        conn

      {:error, retry_after, limit} ->
        conn
        |> put_resp_header("retry-after", Integer.to_string(retry_after))
        |> put_status(:too_many_requests)
        |> json(
          Errors.body(conn, "RATE_LIMITED", "Rate limit exceeded", %{
            limit: limit,
            window_seconds: 60
          })
        )
        |> halt()

      {:error, _reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(Errors.body(conn, "RATE_LIMIT_UNAVAILABLE", "Rate limiter unavailable"))
        |> halt()
    end
  end
end
