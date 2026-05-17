defmodule ConfigManager.Auth.AdminSeederTest do
  use ConfigManager.DataCase, async: false

  import ExUnit.CaptureIO

  alias ConfigManager.Auth.AdminSeeder
  alias ConfigManager.Auth.{ApiToken, Session, User}
  alias ConfigManager.Repo

  setup do
    previous_password = Application.get_env(:config_manager, :bootstrap_admin_password)
    previous_env_user = System.get_env("RAVENWIRE_ADMIN_USER")
    previous_env_password = System.get_env("RAVENWIRE_ADMIN_PASSWORD")

    Repo.delete_all(ApiToken)
    Repo.delete_all(Session)
    Repo.delete_all(User)

    on_exit(fn ->
      Application.put_env(:config_manager, :bootstrap_admin_password, previous_password)
      restore_env("RAVENWIRE_ADMIN_USER", previous_env_user)
      restore_env("RAVENWIRE_ADMIN_PASSWORD", previous_env_password)
    end)

    System.delete_env("RAVENWIRE_ADMIN_USER")
    System.delete_env("RAVENWIRE_ADMIN_PASSWORD")

    :ok
  end

  test "seed! creates first platform admin with configured password" do
    Application.put_env(:config_manager, :bootstrap_admin_password, "configured-password")
    System.delete_env("RAVENWIRE_ADMIN_PASSWORD")

    assert :ok = AdminSeeder.seed!()

    user = Repo.get_by!(User, username: "ravenwire")
    assert user.role == "platform-admin"
    assert user.display_name == "RavenWire Administrator"
    refute user.must_change_password
  end

  test "seed! creates first platform admin from environment variables" do
    Application.delete_env(:config_manager, :bootstrap_admin_password)
    System.put_env("RAVENWIRE_ADMIN_USER", "EnvAdmin")
    System.put_env("RAVENWIRE_ADMIN_PASSWORD", "environment-password")

    assert :ok = AdminSeeder.seed!()

    user = Repo.get_by!(User, username: "envadmin")
    assert user.role == "platform-admin"
    refute user.must_change_password
  end

  test "seed! generates and prints a one-time bootstrap password when none is configured" do
    Application.delete_env(:config_manager, :bootstrap_admin_password)

    output =
      capture_io(fn ->
        assert :ok = AdminSeeder.seed!()
      end)

    assert output =~ "RAVENWIRE_BOOTSTRAP_ADMIN_USER=RavenWire"
    assert output =~ "RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD="

    [password_line] =
      output
      |> String.split("\n", trim: true)
      |> Enum.filter(&String.starts_with?(&1, "RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD="))

    generated_password =
      String.replace_prefix(password_line, "RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD=", "")

    assert String.length(generated_password) == 24

    user = Repo.get_by!(User, username: "ravenwire")
    assert user.must_change_password
    refute user.password_hash =~ generated_password

    refute capture_io(fn -> assert :ok = AdminSeeder.seed!() end) =~
             "RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD="
  end

  test "seed! is a no-op when any user already exists" do
    Application.put_env(:config_manager, :bootstrap_admin_password, "configured-password")
    assert :ok = AdminSeeder.seed!()
    first_count = Repo.aggregate(User, :count)

    Application.put_env(:config_manager, :bootstrap_admin_password, "another-password")
    assert :ok = AdminSeeder.seed!()
    assert Repo.aggregate(User, :count) == first_count
  end

  test "seed! rejects too-short configured bootstrap password" do
    Application.put_env(:config_manager, :bootstrap_admin_password, "short")

    assert_raise RuntimeError, ~r/must be at least/, fn ->
      AdminSeeder.seed!()
    end
  end

  defp restore_env(key, nil), do: System.delete_env(key)
  defp restore_env(key, value), do: System.put_env(key, value)
end
