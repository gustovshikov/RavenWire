defmodule ConfigManager.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    grpc_port = Application.get_env(:config_manager, :grpc_port, 9090)
    ca_path = Application.get_env(:config_manager, :ca_path, "/etc/sensor/certs")

    _grpc_tls_opts = build_grpc_tls_opts(ca_path)

    children =
      [
        # Database
        ConfigManager.Repo,

        # Login attempt rate limiting
        ConfigManager.Auth.RateLimiter,

        # Per-token Public API rate limiting
        ConfigManagerWeb.Api.RateLimiter,

        # Periodic cleanup for expired browser sessions
        ConfigManager.Auth.SessionPruner,

        # Bootstrap local admin account when the users table is empty
        ConfigManager.Auth.AdminSeeder,

        # PubSub for LiveView
        {Phoenix.PubSub, name: ConfigManager.PubSub},

        # Health registry (in-memory pod state)
        ConfigManager.Health.Registry
      ] ++
        metrics_sampler_children() ++
        alert_engine_children() ++
        [
          # Sensor detail actions run off the LiveView process so slow Control API
          # calls can be timed out without blocking UI state updates.
          {Task.Supervisor, name: ConfigManager.SensorActionTaskSupervisor},

          # Deployment orchestration runs in supervised tasks so deployment creation
          # can return promptly while per-sensor push results stream in.
          {Task.Supervisor, name: ConfigManager.Deployments.TaskSupervisor},

          # Rule repository updates fetch and parse archives outside request processes.
          {Task.Supervisor, name: ConfigManager.Rules.TaskSupervisor},

          # BPF validation shells out to tcpdump under an isolated async supervisor.
          {Task.Supervisor, name: ConfigManager.Bpf.TaskSupervisor},

          # Forwarding sink connection checks run outside LiveView/request processes.
          {Task.Supervisor, name: ConfigManager.Forwarding.TaskSupervisor},

          # PCAP carve status polling runs outside LiveView/request processes.
          {Task.Supervisor, name: ConfigManager.Pcap.TaskSupervisor},

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

  defp alert_engine_children do
    if Application.get_env(:config_manager, :alert_engine_enabled, true),
      do: [ConfigManager.Alerts.AlertEngine],
      else: []
  end

  defp metrics_sampler_children do
    if Application.get_env(:config_manager, :metrics_sampler_enabled, true),
      do: [ConfigManager.Metrics.Sampler],
      else: []
  end

  @impl true
  def config_change(changed, _new, removed) do
    ConfigManagerWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
