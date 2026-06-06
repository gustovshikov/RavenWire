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

config :argon2_elixir,
  t_cost: 1,
  m_cost: 8,
  parallelism: 1,
  argon2_type: 2

config :config_manager,
  ca_path: System.tmp_dir!() |> Path.join("config_manager_test_ca"),
  grpc_port: System.get_env("SENSOR_GRPC_PORT", "9090") |> String.to_integer(),
  allow_plain_cert_rotation: true,
  alert_engine_enabled: false,
  metrics_sampler_enabled: false,
  metrics_sample_interval_ms: 1_000,
  metrics_retention_hours: 1,
  metrics_prune_interval_ms: 1_000,
  metrics_prune_batch_size: 100,
  metrics_chart_point_limit: 50,
  baselines_worker_enabled: false,
  baseline_window_hours: 48,
  baseline_min_samples: 3,
  baseline_recompute_interval_ms: 100,
  anomaly_default_sigma: 3.0,
  anomaly_cooldown_minutes: 1,
  anomaly_min_delta_by_metric: %{},
  anomaly_sigma_by_metric: %{},
  capacity_forecast_horizon_hours: 24,
  capacity_forecast_interval_ms: 100,
  capacity_min_forecast_samples: 3,
  bootstrap_admin_password: "test-admin-password"

config :swoosh, :api_client, Swoosh.ApiClient.Test
