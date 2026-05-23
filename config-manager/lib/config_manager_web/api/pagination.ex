defmodule ConfigManagerWeb.Api.Pagination do
  @moduledoc "Shared pagination metadata helpers for the Public API."

  def meta(result) when is_map(result) do
    result
    |> Map.take([:page, :page_size, :total_count, :total_pages])
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
  end

  def parameters(default_page_size \\ 25) do
    [
      %{
        "name" => "page",
        "in" => "query",
        "required" => false,
        "schema" => %{"type" => "integer", "minimum" => 1, "default" => 1}
      },
      %{
        "name" => "page_size",
        "in" => "query",
        "required" => false,
        "schema" => %{
          "type" => "integer",
          "minimum" => 1,
          "maximum" => 250,
          "default" => default_page_size
        }
      }
    ]
  end
end
