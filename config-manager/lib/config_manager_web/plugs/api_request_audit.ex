defmodule ConfigManagerWeb.Plugs.ApiRequestAudit do
  @moduledoc "Records request-level audit entries for authenticated Public API requests."

  import Plug.Conn

  alias ConfigManager.Audit
  alias ConfigManagerWeb.Api.{Errors, Spec}

  def init(opts), do: opts

  def call(conn, _opts) do
    register_before_send(conn, &audit_request/1)
  end

  defp audit_request(conn) do
    token = conn.assigns[:current_token]

    if token do
      operation = Spec.operation_for(conn.method, conn.request_path)
      status = conn.status || 0
      path_template = operation_path(operation, conn.request_path)

      Audit.log(%{
        actor: token.name,
        actor_type: "api_token",
        action: "api_request",
        target_type: "api_route",
        target_id: path_template,
        result: if(status < 400, do: "success", else: "failure"),
        detail: %{
          method: conn.method,
          path_template: path_template,
          status: status,
          required_permission: operation && operation.permission,
          request_id: Errors.request_id(conn),
          token_id: token.id
        }
      })
    end

    conn
  end

  defp operation_path(nil, request_path), do: request_path
  defp operation_path(operation, _request_path), do: operation.router_path
end
