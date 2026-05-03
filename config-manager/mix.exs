defmodule ConfigManager.MixProject do
  use Mix.Project

  def project do
    [
      app: :config_manager,
      version: "0.1.0",
      elixir: "~> 1.19",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      listeners: [Phoenix.CodeReloader]
    ]
  end

  def application do
    [
      mod: {ConfigManager.Application, []},
      extra_applications: [:logger, :runtime_tools, :crypto, :public_key]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Phoenix
      {:phoenix, "~> 1.8"},
      {:phoenix_live_view, "~> 1.1"},
      {:phoenix_html, "~> 4.0"},
      {:phoenix_live_reload, "~> 1.4", only: :dev},
      {:phoenix_ecto, "~> 4.4"},

      # Database
      {:ecto_sql, "~> 3.11"},
      {:ecto_sqlite3, "~> 0.15"},

      # HTTP client
      {:finch, "~> 0.18"},
      {:mint, "~> 1.5"},

      # gRPC (health stream server)
      {:grpc, "~> 0.8"},
      {:protobuf, "~> 0.12"},

      # Certificates and PKI
      {:x509, "~> 0.8"},

      # Metrics
      {:telemetry_metrics, "~> 1.1"},
      {:telemetry_poller, "~> 1.0"},
      {:prometheus_ex, "~> 5.1"},

      # JSON
      {:jason, "~> 1.4"},

      # Authentication
      {:argon2_elixir, "~> 4.1"},

      # Property-based testing
      {:propcheck, "~> 1.4", only: [:test, :dev]},

      # Plug
      {:plug_cowboy, "~> 2.7"},
      {:bandit, "~> 1.2"},

      # Utilities
      {:gettext, "~> 1.0"},
      {:swoosh, "~> 1.14"},
      {:floki, ">= 0.30.0", only: :test}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end
end
