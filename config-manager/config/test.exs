import Config

config :config_manager, ConfigManager.Repo,
  database: "/tmp/config_manager_test.db",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 5

config :config_manager, ConfigManagerWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "test_secret_key_base_at_least_64_chars_long_for_testing_only_not_prod",
  server: false

config :logger, level: :warning
config :phoenix, :plug_init_mode, :runtime

config :config_manager,
  ca_path: System.tmp_dir!() |> Path.join("config_manager_test_ca"),
  grpc_port: 9090,
  allow_plain_cert_rotation: true

config :swoosh, :api_client, Swoosh.ApiClient.Test
