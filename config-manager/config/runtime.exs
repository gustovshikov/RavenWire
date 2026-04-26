import Config

# Runtime configuration — reads environment variables at startup.
# All sensitive values must be provided via environment variables in production.

db_path = System.get_env("SENSOR_DB_PATH", "/data/config_manager.db")
ca_path = System.get_env("SENSOR_CA_PATH", "/data/ca")
port = String.to_integer(System.get_env("SENSOR_PORT", "8443"))
grpc_port = String.to_integer(System.get_env("SENSOR_GRPC_PORT", "9090"))
tls_cert = System.get_env("SENSOR_TLS_CERT")
tls_key = System.get_env("SENSOR_TLS_KEY")
secret_key_base =
  if config_env() == :prod do
    System.get_env("SECRET_KEY_BASE") ||
      raise "SECRET_KEY_BASE environment variable is required in production"
  else
    System.get_env("SECRET_KEY_BASE", String.duplicate("dev_only_not_secret_", 3))
  end
phx_host = System.get_env("PHX_HOST", "localhost")

if config_env() == :prod do
  config :config_manager, ConfigManager.Repo,
    database: db_path,
    journal_mode: :wal,
    busy_timeout: 5000
end

if config_env() == :prod do
  config :config_manager,
    ca_path: ca_path,
    grpc_port: grpc_port
end

if config_env() == :prod do
  tls_opts =
    if tls_cert && tls_key do
      [
        certfile: tls_cert,
        keyfile: tls_key,
        # mTLS: require and verify client certificates
        verify: :verify_peer,
        fail_if_no_peer_cert: true,
        cacertfile: Path.join(ca_path, "intermediate-ca.cert.pem"),
        # Reject expired or revoked certs — additional checks in MTLSAuth plug
        depth: 3,
        versions: [:"tlsv1.3", :"tlsv1.2"],
        ciphers: [
          "TLS_AES_256_GCM_SHA384",
          "TLS_AES_128_GCM_SHA256",
          "ECDHE-ECDSA-AES256-GCM-SHA384",
          "ECDHE-ECDSA-AES128-GCM-SHA256"
        ]
      ]
    else
      []
    end

  config :config_manager, ConfigManagerWeb.Endpoint,
    url: [host: phx_host, port: port, scheme: "https"],
    http: [ip: {0, 0, 0, 0}, port: port],
    https: [ip: {0, 0, 0, 0}, port: port] ++ tls_opts,
    secret_key_base: secret_key_base,
    server: true
end
