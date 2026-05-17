defmodule ConfigManager.Rules.ParserPropTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Rules.Parser

  property "Property 1: Suricata rule parsing round-trip",
           [:verbose, numtests: 80] do
    forall code <- integer(1, 999_999) do
      rule = generated_rule(code)

      {:ok, parsed} = Parser.parse_rule(rule)
      formatted = Parser.format_rule(parsed)
      {:ok, reparsed} = Parser.parse_rule(formatted)

      parsed.sid == code and
        reparsed.sid == parsed.sid and
        reparsed.message == parsed.message and
        reparsed.revision == parsed.revision and
        reparsed.classtype == parsed.classtype
    end
  end

  property "category_from_filename strips paths and .rules extensions",
           [:verbose, numtests: 60] do
    forall code <- integer(1, 10_000) do
      category = "category-#{code}"

      Parser.category_from_filename("/tmp/rules/#{category}.rules") == category and
        Parser.category_from_filename(category <> ".rules") == category
    end
  end

  property "parse_files skips comment and blank lines while parsing valid rules",
           [:verbose, numtests: 60] do
    forall code <- integer(1, 999_999) do
      content = """
      # comment

      #{generated_rule(code)}
      #alert tcp any any -> any any (msg:"disabled"; sid:#{code + 1};)
      """

      {:ok, parsed} = Parser.parse_files([{"rules/generated.rules", content}])

      length(parsed) == 1 and
        List.first(parsed).sid == code and
        List.first(parsed).category == "generated"
    end
  end

  defp generated_rule(sid) do
    revision = rem(sid, 99) + 1
    classtype = Enum.at(["trojan-activity", "attempted-admin", "policy-violation"], rem(sid, 3))

    ~s|alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Generated rule #{sid}"; classtype:#{classtype}; sid:#{sid}; rev:#{revision};)|
  end
end
