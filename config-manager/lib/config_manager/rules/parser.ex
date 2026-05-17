defmodule ConfigManager.Rules.Parser do
  @moduledoc "Parser helpers for Suricata rule store imports."

  require Logger

  @sid_regex ~r/(?:^|[;(])\s*sid\s*:\s*(\d+)\s*;/i
  @revision_regex ~r/(?:^|[;(])\s*rev\s*:\s*(\d+)\s*;/i
  @classtype_regex ~r/(?:^|[;(])\s*classtype\s*:\s*([^;]+)\s*;/i
  @message_regex ~r/(?:^|[;(])\s*msg\s*:\s*"((?:\\.|[^"\\])*)"\s*;/i

  def parse_rule(line) when is_binary(line) do
    rule = String.trim(line)

    cond do
      rule == "" ->
        {:error, :blank}

      comment?(rule) ->
        {:error, :comment}

      disabled_rule?(rule) ->
        {:error, :disabled}

      true ->
        with {:ok, sid} <- extract_sid(rule),
             {:ok, message} <- extract_message(rule) do
          {:ok,
           %{
             sid: sid,
             message: message,
             revision: extract_revision(rule),
             classtype: extract_classtype(rule),
             raw_text: rule
           }}
        end
    end
  end

  def parse_rule(_line), do: {:error, :invalid_rule}

  def extract_sid(line) when is_binary(line) do
    case Regex.run(@sid_regex, line) do
      [_match, sid] -> {:ok, String.to_integer(sid)}
      nil -> {:error, :missing_sid}
    end
  end

  def extract_sid(_line), do: {:error, :missing_sid}

  def extract_message(line) when is_binary(line) do
    case Regex.run(@message_regex, line) do
      [_match, message] -> {:ok, unescape_message(message)}
      nil -> {:error, :missing_message}
    end
  end

  def extract_message(_line), do: {:error, :missing_message}

  def extract_revision(line) when is_binary(line) do
    case Regex.run(@revision_regex, line) do
      [_match, revision] -> String.to_integer(revision)
      nil -> 1
    end
  end

  def extract_revision(_line), do: 1

  def extract_classtype(line) when is_binary(line) do
    case Regex.run(@classtype_regex, line) do
      [_match, classtype] -> String.trim(classtype)
      nil -> nil
    end
  end

  def extract_classtype(_line), do: nil

  def category_from_filename(filename) do
    filename
    |> to_string()
    |> Path.basename()
    |> String.replace_suffix(".rules", "")
  end

  def parse_files(files) when is_list(files) do
    rules =
      files
      |> Enum.flat_map(fn {filename, content} ->
        category = category_from_filename(filename)

        content
        |> logical_lines()
        |> Enum.flat_map(&parse_file_line(&1, category, filename))
      end)

    {:ok, rules}
  end

  def parse_files(_files), do: {:error, :invalid_files}

  def format_rule(rule) when is_map(rule) do
    sid = Map.fetch!(rule, :sid)
    message = Map.fetch!(rule, :message)
    revision = Map.get(rule, :revision) || 1
    classtype = Map.get(rule, :classtype)

    options =
      [
        ~s(msg:"#{escape_message(message)}";),
        if(classtype not in [nil, ""], do: "classtype:#{classtype};"),
        "sid:#{sid};",
        "rev:#{revision};"
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" ")

    "alert ip any any -> any any (#{options})"
  end

  defp parse_file_line(line, category, filename) do
    case parse_rule(line) do
      {:ok, rule} ->
        [Map.put(rule, :category, category)]

      {:error, reason} when reason in [:blank, :comment, :disabled] ->
        []

      {:error, reason} ->
        Logger.warning("Skipping unparseable Suricata rule in #{filename}: #{inspect(reason)}")
        []
    end
  end

  defp logical_lines(content) when is_binary(content) do
    content
    |> String.split(~r/\R/, trim: false)
    |> Enum.reduce({"", []}, fn line, {current, acc} ->
      trimmed = String.trim_trailing(line)

      if String.ends_with?(trimmed, "\\") do
        continued = trimmed |> String.trim_trailing("\\") |> String.trim_trailing()
        {join_rule_parts(current, continued), acc}
      else
        complete = join_rule_parts(current, trimmed)
        {"", [complete | acc]}
      end
    end)
    |> then(fn
      {"", acc} -> acc
      {current, acc} -> [current | acc]
    end)
    |> Enum.reverse()
  end

  defp logical_lines(_content), do: []

  defp join_rule_parts("", part), do: String.trim(part)
  defp join_rule_parts(current, part), do: String.trim(current <> " " <> String.trim(part))

  defp comment?("#" <> rest), do: not disabled_rule?("#" <> rest) and String.trim(rest) != ""
  defp comment?(_line), do: false

  defp disabled_rule?(line), do: String.match?(line, ~r/^#\s*(alert|drop|reject|pass)\b/i)

  defp unescape_message(message) do
    message
    |> String.replace("\\\"", "\"")
    |> String.replace("\\\\", "\\")
  end

  defp escape_message(message) do
    message
    |> to_string()
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end
end
