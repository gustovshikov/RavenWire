# Seeds — create a default sensor pool on first boot.
alias ConfigManager.{Repo, SensorPool}

case Repo.get_by(SensorPool, name: "default") do
  nil ->
    %SensorPool{}
    |> SensorPool.changeset(%{
      name: "default",
      capture_mode: "alert_driven",
      config_updated_at: DateTime.utc_now(),
      config_updated_by: "system"
    })
    |> Repo.insert!()

    IO.puts("Created default sensor pool.")

  _existing ->
    IO.puts("Default sensor pool already exists.")
end
