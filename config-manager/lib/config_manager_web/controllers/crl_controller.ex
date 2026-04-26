defmodule ConfigManagerWeb.CRLController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.CA.CRLStore

  # GET /api/v1/crl
  # Returns the current CRL in DER format for distribution to Sensor_Agents.
  def show(conn, _params) do
    case CRLStore.current_crl_der() do
      {:ok, der} ->
        conn
        |> put_resp_content_type("application/pkix-crl")
        |> send_resp(200, der)

      {:error, reason} ->
        conn
        |> put_status(503)
        |> json(%{error: %{code: "CRL_UNAVAILABLE", message: inspect(reason)}})
    end
  end
end
