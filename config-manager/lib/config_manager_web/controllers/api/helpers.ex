defmodule ConfigManagerWeb.Api.Helpers do
  @moduledoc false

  import Plug.Conn
  import Phoenix.Controller

  alias ConfigManager.Auth.ApiToken
  alias Ecto.Changeset

  def current_actor(conn) do
    conn.assigns[:current_token] || conn.assigns[:current_user] || "api"
  end

  def actor_name(%Plug.Conn{} = conn), do: conn |> current_actor() |> actor_name()
  def actor_name(%ApiToken{name: name}), do: name
  def actor_name(%{username: username}), do: username
  def actor_name(actor) when is_binary(actor), do: actor
  def actor_name(_actor), do: "api"

  def actor_type(%Plug.Conn{} = conn), do: conn |> current_actor() |> actor_type()
  def actor_type(%ApiToken{}), do: "api_token"
  def actor_type(%{username: _username}), do: "user"
  def actor_type("system"), do: "system"
  def actor_type(_actor), do: "api_token"

  def page_opts(params, default_page_size \\ 25) do
    [
      page: int_param(params, "page", 1),
      page_size: int_param(params, "page_size", default_page_size)
    ]
  end

  def int_param(params, key, default) do
    case Map.get(params, key, Map.get(params, String.to_atom(key), default)) do
      value when is_integer(value) ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _rest} -> int
          :error -> default
        end

      _value ->
        default
    end
  end

  def bool_param(params, key, default) do
    case Map.get(params, key, Map.get(params, String.to_atom(key), default)) do
      value when is_boolean(value) -> value
      value when value in ["true", "1", "yes", "on"] -> true
      value when value in ["false", "0", "no", "off"] -> false
      _value -> default
    end
  end

  def api_error(conn, status, code, message, details \\ nil) do
    error = %{code: code, message: message}
    error = if is_nil(details), do: error, else: Map.put(error, :details, details)

    conn
    |> put_status(status)
    |> json(%{error: error})
  end

  def changeset_error(conn, %Changeset{} = changeset) do
    api_error(conn, :unprocessable_entity, "VALIDATION_FAILED", "Validation failed", %{
      fields: changeset_errors(changeset)
    })
  end

  def not_found(conn, resource) do
    api_error(conn, :not_found, "NOT_FOUND", "#{resource} not found")
  end

  def unsupported(conn, feature) do
    api_error(conn, :not_implemented, "NOT_IMPLEMENTED", "#{feature} is not implemented")
  end

  def action_error(conn, reason) do
    api_error(conn, :unprocessable_entity, "ACTION_FAILED", format_reason(reason))
  end

  def format_reason(reason) when is_atom(reason),
    do: reason |> Atom.to_string() |> String.replace("_", " ")

  def format_reason(reason) when is_binary(reason), do: reason
  def format_reason(reason), do: inspect(reason)

  def changeset_errors(%Changeset{} = changeset) do
    Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
