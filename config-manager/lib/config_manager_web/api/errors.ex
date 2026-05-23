defmodule ConfigManagerWeb.Api.Errors do
  @moduledoc "Helpers for Public API error envelopes and OpenAPI error responses."

  import Plug.Conn

  @standard_errors [
    bad_request: {400, "BAD_REQUEST", "Bad request"},
    unauthorized: {401, "UNAUTHORIZED", "Invalid or missing bearer token"},
    forbidden: {403, "FORBIDDEN", "Insufficient permissions"},
    not_found: {404, "NOT_FOUND", "Resource not found"},
    conflict: {409, "CONFLICT", "Request conflicts with current resource state"},
    gone: {410, "GONE", "Resource is no longer available"},
    unprocessable_entity: {422, "VALIDATION_FAILED", "Validation failed"},
    too_many_requests: {429, "RATE_LIMITED", "Rate limit exceeded"},
    service_unavailable: {503, "SERVICE_UNAVAILABLE", "Service unavailable"}
  ]

  def body(conn, code, message, details \\ nil) do
    error = %{code: code, message: message}
    error = if is_nil(details), do: error, else: Map.put(error, :details, details)

    case request_id(conn) do
      nil -> %{error: error}
      request_id -> %{error: Map.put(error, :request_id, request_id)}
    end
  end

  def request_id(conn) do
    conn
    |> get_resp_header("x-request-id")
    |> List.first()
    |> case do
      nil -> conn |> get_req_header("x-request-id") |> List.first()
      request_id -> request_id
    end
  end

  def standard_responses do
    @standard_errors
    |> Enum.map(fn {_name, {status, code, message}} ->
      {Integer.to_string(status), response(message, code, message)}
    end)
    |> Map.new()
  end

  def response(description, code, message) do
    %{
      "description" => description,
      "content" => %{
        "application/json" => %{
          "schema" => %{"$ref" => "#/components/schemas/ErrorResponse"},
          "example" => %{
            "error" => %{
              "code" => code,
              "message" => message,
              "request_id" => "Fz3ExampleRequestId"
            }
          }
        }
      }
    }
  end
end
