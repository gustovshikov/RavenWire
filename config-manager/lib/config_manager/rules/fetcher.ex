defmodule ConfigManager.Rules.Fetcher do
  @moduledoc "Fetches Suricata rule archives and extracts parsed rule data."

  alias ConfigManager.Rules.Parser

  @fetch_timeout_ms 60_000

  def fetch(url, requester \\ ConfigManager.Finch)

  def fetch(url, requester) when is_binary(url) do
    request = Finch.build(:get, url)

    case request(request, requester) do
      {:ok, %Finch.Response{status: status, body: body}} when status in 200..299 ->
        {:ok, body}

      {:ok, %Finch.Response{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        {:error, {:request_failed, reason}}
    end
  end

  def fetch(_url, _requester), do: {:error, :invalid_url}

  def extract(archive_data) when is_binary(archive_data) do
    archive_data
    |> extract_archive()
    |> case do
      {:ok, files} ->
        files
        |> Enum.flat_map(&rules_file/1)
        |> Enum.sort_by(fn {filename, _content} -> filename end)
        |> case do
          [] -> {:error, :empty_archive}
          rules_files -> {:ok, rules_files}
        end

      {:error, reason} ->
        {:error, {:invalid_archive, reason}}
    end
  rescue
    error -> {:error, {:invalid_archive, error}}
  end

  def extract(_archive_data), do: {:error, :invalid_archive}

  def fetch_and_parse(url, requester \\ ConfigManager.Finch) do
    with {:ok, archive_data} <- fetch(url, requester),
         {:ok, files} <- extract(archive_data) do
      Parser.parse_files(files)
    end
  end

  defp request(request, requester) when is_function(requester, 1), do: requester.(request)

  defp request(request, requester) do
    Finch.request(request, requester, receive_timeout: @fetch_timeout_ms)
  end

  defp extract_archive(archive_data) do
    :erl_tar.extract({:binary, archive_data}, [:compressed, :memory])
  end

  defp rules_file({filename, content}) when is_binary(content) do
    filename = filename_to_string(filename)

    if String.ends_with?(filename, ".rules") do
      [{filename, content}]
    else
      []
    end
  end

  defp rules_file(_entry), do: []

  defp filename_to_string(filename) when is_binary(filename), do: filename
  defp filename_to_string(filename) when is_list(filename), do: List.to_string(filename)
  defp filename_to_string(filename), do: to_string(filename)
end
