defmodule ConfigManager.Auth.AdminSeeder do
  @moduledoc "Creates the first platform-admin user when no users exist."

  use GenServer
  require Logger

  alias ConfigManager.Auth
  alias ConfigManager.Auth.Password
  alias ConfigManager.Repo

  def start_link(_opts), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @impl true
  def init(:ok) do
    seed!()
    {:ok, %{}}
  end

  def seed! do
    if Repo.aggregate(ConfigManager.Auth.User, :count, :id) == 0 do
      username = System.get_env("RAVENWIRE_ADMIN_USER", "RavenWire")

      password =
        Application.get_env(:config_manager, :bootstrap_admin_password) ||
          System.get_env("RAVENWIRE_ADMIN_PASSWORD")

      {password, must_change_password} =
        case password do
          nil ->
            generated = Password.generate_random_password()

            IO.puts("""
            RAVENWIRE_BOOTSTRAP_ADMIN_USER=#{username}
            RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD=#{generated}
            RavenWire bootstrap admin password is printed once. Change it after first login.
            """)

            {generated, true}

          value ->
            if String.length(value) < Password.min_length() do
              raise "RAVENWIRE_ADMIN_PASSWORD must be at least #{Password.min_length()} characters"
            end

            {value, false}
        end

      {:ok, _user} =
        Auth.create_user(%{
          username: username,
          display_name: "RavenWire Administrator",
          role: "platform-admin",
          active: true,
          must_change_password: must_change_password,
          password: password
        })

      Logger.info("Created initial RavenWire platform-admin user #{inspect(username)}")
    end

    :ok
  end
end
