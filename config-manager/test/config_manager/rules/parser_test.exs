defmodule ConfigManager.Rules.ParserTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Rules.Parser

  test "parses known Suricata rule metadata" do
    rule =
      ~s|alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Possible callback"; flow:established,to_server; classtype:trojan-activity; sid:2019999; rev:7;)|

    assert {:ok, parsed} = Parser.parse_rule(rule)
    assert parsed.sid == 2_019_999
    assert parsed.message == "ET MALWARE Possible callback"
    assert parsed.revision == 7
    assert parsed.classtype == "trojan-activity"
    assert parsed.raw_text == rule
  end

  test "extracts SID with flexible spacing and SID at end of options" do
    rule = ~s|alert tcp any any -> any any (msg:"sid spacing"; rev:2; sid: 42 ;)|

    assert {:ok, 42} = Parser.extract_sid(rule)
    assert {:ok, parsed} = Parser.parse_rule(rule)
    assert parsed.sid == 42
  end

  test "extracts messages with escaped quotes" do
    rule = ~s|alert tcp any any -> any any (msg:"ET EXPLOIT \\\"quoted\\\" marker"; sid:43;)|

    assert {:ok, "ET EXPLOIT \"quoted\" marker"} = Parser.extract_message(rule)
    assert {:ok, parsed} = Parser.parse_rule(rule)
    assert parsed.message == "ET EXPLOIT \"quoted\" marker"
  end

  test "defaults missing revision and allows missing classtype" do
    rule = ~s|alert udp any any -> any any (msg:"minimal"; sid:44;)|

    assert {:ok, parsed} = Parser.parse_rule(rule)
    assert parsed.revision == 1
    assert parsed.classtype == nil
  end

  test "derives category from rule filename paths" do
    assert Parser.category_from_filename("rules/emerging-malware.rules") == "emerging-malware"
    assert Parser.category_from_filename("/tmp/community.rules") == "community"
  end

  test "parse_files skips comments, disabled rules, blanks, invalid lines, and handles continuations" do
    content = """
    # plain comment

    # alert tcp any any -> any any (msg:"disabled"; sid:10;)
    alert tcp any any -> any any \\
      (msg:"continued"; classtype:attempted-admin; sid:11; rev:2;)
    not a rule
    alert udp any any -> any any (msg:"second"; sid:12;)
    """

    assert {:ok, parsed} = Parser.parse_files([{"rules/emerging-exploit.rules", content}])

    assert Enum.map(parsed, & &1.sid) == [11, 12]
    assert Enum.all?(parsed, &(&1.category == "emerging-exploit"))
    assert Enum.at(parsed, 0).message == "continued"
    assert Enum.at(parsed, 0).classtype == "attempted-admin"
  end

  test "format_rule produces parseable Suricata syntax" do
    formatted =
      Parser.format_rule(%{
        sid: 55,
        message: "formatted \"message\"",
        revision: 3,
        classtype: "policy-violation"
      })

    assert {:ok, parsed} = Parser.parse_rule(formatted)
    assert parsed.sid == 55
    assert parsed.message == "formatted \"message\""
    assert parsed.revision == 3
    assert parsed.classtype == "policy-violation"
  end

  test "parse_rule rejects blank, comment, disabled, and metadata-incomplete lines" do
    assert {:error, :blank} = Parser.parse_rule("")
    assert {:error, :comment} = Parser.parse_rule("# comment")

    assert {:error, :disabled} =
             Parser.parse_rule("#alert tcp any any -> any any (msg:\"x\"; sid:1;)")

    assert {:error, :missing_sid} = Parser.parse_rule(~s|alert tcp any any -> any any (msg:"x";)|)
    assert {:error, :missing_message} = Parser.parse_rule("alert tcp any any -> any any (sid:1;)")
  end
end
