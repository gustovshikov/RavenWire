defmodule ConfigManagerWeb.CoreComponents do
  @moduledoc "Core reusable UI components."

  use Phoenix.Component

  attr :flash, :map, required: true

  def flash_group(assigns) do
    ~H"""
    <%= for {kind, msg} <- @flash do %>
      <div class={"flash flash-#{kind}"}><%= msg %></div>
    <% end %>
    """
  end
end
