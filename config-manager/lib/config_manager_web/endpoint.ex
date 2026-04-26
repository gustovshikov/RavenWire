defmodule ConfigManagerWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :config_manager

  # Session configuration
  @session_options [
    store: :cookie,
    key: "_config_manager_key",
    signing_salt: "sensor_stack_lv",
    same_site: "Lax"
  ]

  socket "/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [session: @session_options]],
    longpoll: [connect_info: [session: @session_options]]

  plug Plug.Static,
    at: "/",
    from: :config_manager,
    gzip: false,
    only: ConfigManagerWeb.static_paths()

  if code_reloading? do
    plug Phoenix.CodeReloader
    plug Phoenix.Ecto.CheckRepoStatus, otp_app: :config_manager
  end

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.MethodOverride
  plug Plug.Head
  plug Plug.Session, @session_options
  plug ConfigManagerWeb.Router
end
