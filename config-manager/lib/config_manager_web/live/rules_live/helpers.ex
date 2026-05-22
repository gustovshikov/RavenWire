defmodule ConfigManagerWeb.RulesLive.Helpers do
  @moduledoc false

  use Phoenix.Component

  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.Formatters

  def can_manage_rules?(nil), do: false
  def can_manage_rules?(user), do: Policy.has_permission?(user.role, "rules:manage")

  def can_deploy_rules?(nil), do: false
  def can_deploy_rules?(user), do: Policy.has_permission?(user.role, "rules:deploy")

  attr(:active, :string, default: nil)

  def rules_nav(assigns) do
    ~H"""
    <nav class="mb-4 flex flex-wrap gap-3 text-sm" aria-label="Rules navigation">
      <.rules_nav_link href="/rules/store" label="Rule Store" active={@active == "store"} />
      <.rules_nav_link href="/rules/categories" label="Categories" active={@active == "categories"} />
      <.rules_nav_link href="/rules/repositories" label="Repositories" active={@active == "repositories"} />
      <.rules_nav_link href="/rules/rulesets" label="Rulesets" active={@active == "rulesets"} />
      <.rules_nav_link href="/rules/deployments" label="Deployments" active={@active == "deployments"} />
      <.rules_nav_link href="/rules" label="Quick Deploy" active={@active == "quick"} />
    </nav>
    """
  end

  attr(:href, :string, required: true)
  attr(:label, :string, required: true)
  attr(:active, :boolean, default: false)

  def rules_nav_link(assigns) do
    ~H"""
    <a
      href={@href}
      class={
        if @active,
          do: "font-medium text-gray-900 underline decoration-blue-500 underline-offset-4",
          else: "text-blue-600 hover:underline"
      }
    >
      <%= @label %>
    </a>
    """
  end

  def enabled_label(true), do: "Enabled"
  def enabled_label(false), do: "Disabled"
  def enabled_label(_), do: Formatters.display(nil)

  def enabled_class(true), do: "bg-green-100 text-green-800"
  def enabled_class(false), do: "bg-gray-100 text-gray-700"
  def enabled_class(_), do: "bg-gray-100 text-gray-700"

  def repo_status_label("never_updated"), do: "Never Updated"
  def repo_status_label("updating"), do: "Updating"
  def repo_status_label("success"), do: "Success"
  def repo_status_label("failed"), do: "Failed"
  def repo_status_label(value), do: Formatters.display(value)

  def repo_status_class("success"), do: "bg-green-100 text-green-800"
  def repo_status_class("updating"), do: "bg-blue-100 text-blue-800"
  def repo_status_class("failed"), do: "bg-red-100 text-red-800"
  def repo_status_class(_), do: "bg-gray-100 text-gray-700"

  def sync_status_label(:in_sync), do: "In Sync"
  def sync_status_label(:out_of_sync), do: "Out of Sync"
  def sync_status_label(:no_ruleset_assigned), do: "No Ruleset"
  def sync_status_label(nil), do: "No Ruleset"
  def sync_status_label(value), do: value |> to_string() |> String.replace("_", " ")

  def sync_status_class(:in_sync), do: "bg-green-100 text-green-800"
  def sync_status_class(:out_of_sync), do: "bg-yellow-100 text-yellow-900"
  def sync_status_class(:no_ruleset_assigned), do: "bg-gray-100 text-gray-700"
  def sync_status_class(nil), do: "bg-gray-100 text-gray-700"
  def sync_status_class(_), do: "bg-gray-100 text-gray-700"

  def format_count(value) when is_integer(value), do: Integer.to_string(value)
  def format_count(value), do: Formatters.display(value)

  def short_id(nil), do: Formatters.display(nil)
  def short_id(id), do: id |> to_string() |> String.slice(0, 8)

  def decoded_detail(nil), do: %{}

  def decoded_detail(detail) when is_binary(detail) do
    case Jason.decode(detail) do
      {:ok, decoded} when is_map(decoded) -> decoded
      _ -> %{}
    end
  end

  def decoded_detail(detail) when is_map(detail), do: detail
  def decoded_detail(_detail), do: %{}

  def deployment_result_summary(detail) do
    detail = decoded_detail(detail)
    results = Map.get(detail, "sensor_results") || Map.get(detail, :sensor_results) || []

    cond do
      is_list(results) and results != [] ->
        successes =
          Enum.count(results, fn result ->
            value = to_string(result_value(result))
            value == "ok" or String.contains?(value, "{:ok")
          end)

        failures = length(results) - successes
        "#{successes} ok / #{failures} failed"

      Map.has_key?(detail, "result_count") ->
        "#{detail["result_count"]} target(s)"

      true ->
        Formatters.display(nil)
    end
  end

  defp result_value(%{"result" => result}), do: result
  defp result_value(%{result: result}), do: result
  defp result_value(result), do: inspect(result)
end
