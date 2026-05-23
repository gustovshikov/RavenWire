defmodule ConfigManager.Bpf.JsonTerm do
  @moduledoc "Ecto type for JSON-backed maps and lists stored as text."

  use Ecto.Type

  def type, do: :string

  def cast(value) when is_map(value) or is_list(value), do: {:ok, value}

  def cast(value) when is_binary(value), do: decode(value)

  def cast(_value), do: :error

  def load(value) when is_binary(value), do: decode(value)

  def load(value) when is_map(value) or is_list(value), do: {:ok, value}

  def load(_value), do: :error

  def dump(value) when is_map(value) or is_list(value), do: encode(value)

  def dump(value) when is_binary(value) do
    with {:ok, decoded} <- decode(value) do
      encode(decoded)
    end
  end

  def dump(_value), do: :error

  defp decode(value) do
    case Jason.decode(value) do
      {:ok, decoded} when is_map(decoded) or is_list(decoded) -> {:ok, decoded}
      _error -> :error
    end
  end

  defp encode(value) do
    case Jason.encode(value) do
      {:ok, encoded} -> {:ok, encoded}
      _error -> :error
    end
  end
end
