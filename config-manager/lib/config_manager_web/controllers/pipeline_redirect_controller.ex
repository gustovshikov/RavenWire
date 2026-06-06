defmodule ConfigManagerWeb.PipelineRedirectController do
  use ConfigManagerWeb, :controller

  def sensor(conn, %{"id" => id}) do
    redirect(conn, to: "/sensors/#{id}/pipeline/graph")
  end
end
