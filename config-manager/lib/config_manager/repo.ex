defmodule ConfigManager.Repo do
  use Ecto.Repo,
    otp_app: :config_manager,
    adapter: Ecto.Adapters.SQLite3
end
