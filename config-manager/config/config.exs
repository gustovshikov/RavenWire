import Config

config :config_manager,
  ecto_repos: [ConfigManager.Repo],
  env: config_env(),
  secure_session_cookie: true,
  api_docs_require_auth: false,
  api_token_rate_limit_per_minute: 100,
  metrics_sampler_enabled: true,
  metrics_sample_interval_ms: 60_000,
  metrics_retention_hours: 72,
  metrics_prune_interval_ms: 900_000,
  metrics_prune_batch_size: 1_000,
  metrics_chart_point_limit: 1_000

config :config_manager, ConfigManager.Repo,
  database: System.get_env("SENSOR_DB_PATH", "/data/config_manager.db"),
  pool_size: 5,
  journal_mode: :wal,
  busy_timeout: 5000

config :config_manager, ConfigManagerWeb.Endpoint,
  url: [host: "localhost"],
  render_errors: [
    formats: [html: ConfigManagerWeb.ErrorHTML, json: ConfigManagerWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: ConfigManager.PubSub,
  live_view: [signing_salt: "sensor_stack_lv"]

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

config :phoenix, :json_library, Jason

config :swoosh, :api_client, Swoosh.ApiClient.Finch
config :swoosh, :finch_name, ConfigManager.Finch

config :config_manager, :clock_drift_threshold_ms, 100

config :argon2_elixir,
  argon2_type: 2,
  t_cost: 2,
  m_cost: 15,
  parallelism: 1

import_config "#{config_env()}.exs"
