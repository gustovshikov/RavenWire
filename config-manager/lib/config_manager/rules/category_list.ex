defmodule ConfigManager.Rules.CategoryList do
  @moduledoc """
  Stores a list of ruleset categories as JSON text for SQLite-backed schemas.
  """

  use Ecto.Type

  def type, do: :string

  def cast(nil), do: {:ok, []}

  def cast(categories) when is_list(categories) do
    categories
    |> Enum.map(&normalize_category/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> then(&{:ok, &1})
  end

  def cast(categories) when is_binary(categories) do
    case Jason.decode(categories) do
      {:ok, decoded} when is_list(decoded) -> cast(decoded)
      _error -> :error
    end
  end

  def cast(_other), do: :error

  def load(nil), do: {:ok, []}

  def load(categories) when is_binary(categories), do: cast(categories)

  def dump(categories) when is_list(categories) do
    categories
    |> Enum.map(&normalize_category/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Jason.encode()
  end

  def dump(_other), do: :error

  def equal?(left, right) do
    normalize_for_compare(left) == normalize_for_compare(right)
  end

  defp normalize_category(category), do: category |> to_string() |> String.trim()

  defp normalize_for_compare(categories) when is_list(categories) do
    categories
    |> Enum.map(&normalize_category/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp normalize_for_compare(_other), do: []
end
