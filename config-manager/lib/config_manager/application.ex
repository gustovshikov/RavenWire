defmodule ConfigManager.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    grpc_port = Application.get_env(:config_manager, :grpc_port, 9090)
    ca_path = Application.get_env(:config_manager, :ca_path, "/etc/sensor/certs")

    _grpc_tls_opts = build_grpc_tls_opts(ca_path)

    children = [
      # Database
      ConfigManager.Repo,

      # Bootstrap local admin account when the users table is empty
      ConfigManager.Auth.AdminSeeder,

      # PubSub for LiveView
      {Phoenix.PubSub, name: ConfigManager.PubSub},

      # Health registry (in-memory pod state)
      ConfigManager.Health.Registry,

      # Intermediate CA — generates or loads keypair from persistent volume
      ConfigManager.CA.IntermediateCA,

      # CRL store — ETS-backed revocation list, loaded from DB on startup
      ConfigManager.CA.CRLStore,

      # Finch HTTP client
      {Finch, name: ConfigManager.Finch},

      # Telemetry
      ConfigManager.Telemetry,

      # gRPC health stream server — accepts Sensor_Agent streams on port 9090 (mTLS)
      {GRPC.Server.Supervisor,
       endpoint: ConfigManager.Health.GrpcEndpoint, port: grpc_port, start_server: true},

      # Phoenix endpoint (port 8443)
      ConfigManagerWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: ConfigManager.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Build mTLS options for the gRPC server.
  # Falls back to plain (no TLS) when cert files are not present — useful in dev/test.
  defp build_grpc_tls_opts(ca_path) do
    cert_file = Path.join(ca_path, "server.cert.pem")
    key_file = Path.join(ca_path, "server.key.pem")
    ca_file = Path.join(ca_path, "intermediate-ca.cert.pem")

    if File.exists?(cert_file) and File.exists?(key_file) and File.exists?(ca_file) do
      [
        cred:
          GRPC.Credential.new(
            ssl: [
              certfile: cert_file,
              keyfile: key_file,
              cacertfile: ca_file,
              verify: :verify_peer,
              fail_if_no_peer_cert: true,
              versions: [:"tlsv1.3", :"tlsv1.2"]
            ]
          )
      ]
    else
      # No TLS in dev/test when certs are absent
      []
    end
  end

  @impl true
  def config_change(changed, _new, removed) do
    ConfigManagerWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
