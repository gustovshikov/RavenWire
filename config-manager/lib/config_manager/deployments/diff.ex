defmodule ConfigManager.Deployments.Diff do
  @moduledoc "Computes secret-safe summaries between deployment snapshots."

  alias ConfigManager.Deployments.Snapshot

  def compute(nil, _current), do: nil

  def compute(previous, current) when is_map(previous) and is_map(current) do
    [
      {"capture", diff_capture(previous["capture"] || %{}, current["capture"] || %{})},
      {"bpf", diff_bpf(previous["bpf"] || %{}, current["bpf"] || %{})},
      {"forwarding",
       diff_forwarding(previous["forwarding"] || %{}, current["forwarding"] || %{})},
      {"rules", diff_rules(previous["rules"] || %{}, current["rules"] || %{})}
    ]
    |> Enum.reject(fn {_domain, diff} -> empty_diff?(diff) end)
    |> Map.new()
  end

  def diff_capture(previous, current), do: changed_fields(previous, current)

  def diff_bpf(previous, current) do
    %{}
    |> put_if_present("fields", changed_fields(previous, current, ["rules"]))
    |> put_if_present("rules", list_diff(previous["rules"] || [], current["rules"] || []))
  end

  def diff_forwarding(previous, current) do
    previous_sinks = sinks_by_name(previous["sinks"] || [])
    current_sinks = sinks_by_name(current["sinks"] || [])

    %{}
    |> put_if_present("fields", changed_fields(previous, current, ["sinks"]))
    |> put_if_present("sinks", keyed_collection_diff(previous_sinks, current_sinks))
  end

  def diff_rules(previous, current) do
    previous_files = previous["files"] || %{}
    current_files = current["files"] || %{}

    %{}
    |> put_if_present("fields", changed_fields(previous, current, ["files"]))
    |> put_if_present("files", keyed_collection_diff(previous_files, current_files))
  end

  defp changed_fields(previous, current, ignored_keys \\ []) do
    keys =
      previous
      |> Map.keys()
      |> Enum.concat(Map.keys(current))
      |> Enum.uniq()
      |> Enum.reject(&(&1 in ignored_keys))

    Enum.reduce(keys, %{}, fn key, acc ->
      old = Map.get(previous, key)
      new = Map.get(current, key)

      if old == new do
        acc
      else
        Map.put(acc, key, %{"old" => redact(old), "new" => redact(new)})
      end
    end)
  end

  defp list_diff(previous, current) do
    previous_set = MapSet.new(previous)
    current_set = MapSet.new(current)

    %{}
    |> put_if_present("added", MapSet.difference(current_set, previous_set) |> MapSet.to_list())
    |> put_if_present("removed", MapSet.difference(previous_set, current_set) |> MapSet.to_list())
  end

  defp keyed_collection_diff(previous, current) do
    previous_keys = previous |> Map.keys() |> MapSet.new()
    current_keys = current |> Map.keys() |> MapSet.new()

    modified =
      previous_keys
      |> MapSet.intersection(current_keys)
      |> Enum.reduce(%{}, fn key, acc ->
        diff = value_diff(Map.fetch!(previous, key), Map.fetch!(current, key))

        if empty_diff?(diff), do: acc, else: Map.put(acc, key, diff)
      end)

    %{}
    |> put_if_present("added", MapSet.difference(current_keys, previous_keys) |> MapSet.to_list())
    |> put_if_present(
      "removed",
      MapSet.difference(previous_keys, current_keys) |> MapSet.to_list()
    )
    |> put_if_present("modified", modified)
  end

  defp sinks_by_name(sinks) do
    sinks
    |> Enum.map(&Snapshot.sanitize_sink/1)
    |> Enum.map(fn sink ->
      name = sink["name"] || sink[:name] || sink["id"] || sink[:id]
      {to_string(name), stringify_keys(sink)}
    end)
    |> Map.new()
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {to_string(key), redact(value)} end)
  end

  defp value_diff(previous, current) when is_map(previous) and is_map(current) do
    changed_fields(previous, current)
  end

  defp value_diff(previous, current) when previous == current, do: %{}
  defp value_diff(previous, current), do: %{"old" => redact(previous), "new" => redact(current)}

  defp redact(value) when is_map(value), do: value |> Snapshot.sanitize_sink() |> stringify_keys()
  defp redact(value) when is_list(value), do: Enum.map(value, &redact/1)
  defp redact(value), do: value

  defp put_if_present(map, _key, value) when value in [%{}, [], nil], do: map
  defp put_if_present(map, key, value), do: Map.put(map, key, value)

  defp empty_diff?(value), do: value in [%{}, [], nil]
end
