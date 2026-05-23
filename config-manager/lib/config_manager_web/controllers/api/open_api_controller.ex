defmodule ConfigManagerWeb.Api.OpenApiController do
  use ConfigManagerWeb, :controller

  import ConfigManagerWeb.Api.Helpers

  alias ConfigManager.Auth
  alias ConfigManagerWeb.Api.Spec

  def show(conn, _params) do
    if docs_auth_required?() do
      case Auth.validate_session(get_session(conn, :session_token)) do
        {:ok, _user} ->
          json(conn, Spec.spec())

        {:error, _reason} ->
          api_error(
            conn,
            :unauthorized,
            "UNAUTHORIZED",
            "API documentation requires authentication"
          )
      end
    else
      json(conn, Spec.spec())
    end
  end

  defp docs_auth_required? do
    Application.get_env(:config_manager, :api_docs_require_auth, false)
  end
end
