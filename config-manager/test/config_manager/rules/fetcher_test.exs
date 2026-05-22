defmodule ConfigManager.Rules.FetcherTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Rules.Fetcher

  test "fetch returns response body for successful HTTP responses" do
    requester = fn _request -> {:ok, %Finch.Response{status: 200, body: "archive"}} end

    assert {:ok, "archive"} =
             Fetcher.fetch("https://rules.example.test/archive.tar.gz", requester)
  end

  test "fetch reports HTTP and transport errors" do
    assert {:error, {:http_error, 404, "missing"}} =
             Fetcher.fetch("https://rules.example.test/missing.tar.gz", fn _request ->
               {:ok, %Finch.Response{status: 404, body: "missing"}}
             end)

    assert {:error, {:request_failed, :timeout}} =
             Fetcher.fetch("https://rules.example.test/timeout.tar.gz", fn _request ->
               {:error, :timeout}
             end)
  end

  test "extract returns only .rules files from tar.gz archives" do
    archive =
      tar_gz!([
        {"rules/emerging-test.rules", generated_rule(1)},
        {"rules/readme.txt", "not a rule"}
      ])

    assert {:ok, [{"rules/emerging-test.rules", content}]} = Fetcher.extract(archive)
    assert content =~ "sid:1;"
  end

  test "extract rejects invalid archives and archives without rule files" do
    assert {:error, {:invalid_archive, _reason}} = Fetcher.extract("not an archive")

    archive = tar_gz!([{"rules/readme.txt", "not a rule"}])
    assert {:error, :empty_archive} = Fetcher.extract(archive)
  end

  test "fetch_and_parse fetches, extracts, and parses archive rules" do
    archive =
      tar_gz!([
        {"rules/emerging-test.rules", generated_rule(42)}
      ])

    requester = fn _request -> {:ok, %Finch.Response{status: 200, body: archive}} end

    assert {:ok, [rule]} =
             Fetcher.fetch_and_parse("https://rules.example.test/archive.tar.gz", requester)

    assert rule.sid == 42
    assert rule.category == "emerging-test"
  end

  defp generated_rule(sid) do
    ~s|alert ip any any -> any any (msg:"Generated #{sid}"; classtype:trojan-activity; sid:#{sid}; rev:1;)|
  end

  defp tar_gz!(entries) do
    path = Path.join(System.tmp_dir!(), "rules-test-#{System.unique_integer([:positive])}.tar.gz")

    tar_entries =
      Enum.map(entries, fn {filename, content} -> {String.to_charlist(filename), content} end)

    :ok = :erl_tar.create(String.to_charlist(path), tar_entries, [:compressed])
    archive = File.read!(path)
    File.rm(path)
    archive
  end
end
