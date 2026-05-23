defmodule ConfigManager.AuthTest do
  use ConfigManager.DataCase, async: false

  import Ecto.Query

  alias ConfigManager.{AuditEntry, Auth}
  alias ConfigManager.Auth.{ApiToken, RateLimiter, Session, SessionPruner, User}
  alias ConfigManager.Repo

  setup do
    previous_ip_limit = System.get_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT")
    RateLimiter.reset()

    on_exit(fn ->
      restore_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT", previous_ip_limit)
    end)

    :ok
  end

  test "create_user normalizes username and authenticate returns a raw session token" do
    password = "long-enough-password"

    assert {:ok, %User{} = user} =
             Auth.create_user(%{
               username: "  MixedCaseUser  ",
               display_name: "Mixed Case",
               role: "viewer",
               password: password
             })

    assert user.username == "mixedcaseuser"
    refute user.password_hash =~ password

    assert {:ok, ^user, token} = Auth.authenticate("MIXEDCASEUSER", password)
    assert is_binary(token)
    assert byte_size(token) > 30

    assert {:ok, %User{id: user_id}} = Auth.validate_session(token)
    assert user_id == user.id
  end

  test "authenticate hides missing, disabled, and bad-password reasons" do
    {:ok, user} =
      Auth.create_user(%{
        username: "disabled-user",
        display_name: "Disabled",
        role: "viewer",
        active: false,
        password: "long-enough-password"
      })

    assert {:error, :invalid_credentials} = Auth.authenticate("missing-user", "anything")

    assert {:error, :invalid_credentials} =
             Auth.authenticate(user.username, "long-enough-password")

    assert {:error, :invalid_credentials} = Auth.authenticate(user.username, "wrong-password")
  end

  test "authenticate rate limits repeated username failures with generic errors and audit detail" do
    {:ok, user} = create_user!("limited-user")

    for _attempt <- 1..5 do
      assert {:error, :invalid_credentials} = Auth.authenticate(user.username, "wrong-password")
    end

    assert {:error, :invalid_credentials} =
             Auth.authenticate(user.username, "long-enough-password")

    audit = Repo.get_by!(AuditEntry, action: "login_rate_limited", target_id: user.username)
    assert audit.actor_type == "anonymous"
    assert Jason.decode!(audit.detail)["reason"] == "rate_limited"

    RateLimiter.reset()

    assert {:ok, %User{id: user_id}, _token} =
             Auth.authenticate(user.username, "long-enough-password")

    assert user_id == user.id
  end

  test "authenticate rate limits repeated IP failures with generic errors and audit detail" do
    System.put_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT", "2")
    ip = {127, 0, 0, 42}

    assert {:error, :invalid_credentials} = Auth.authenticate("missing-ip-1", "wrong", ip: ip)
    assert {:error, :invalid_credentials} = Auth.authenticate("missing-ip-2", "wrong", ip: ip)
    assert {:error, :invalid_credentials} = Auth.authenticate("missing-ip-3", "wrong", ip: ip)

    audit = Repo.get_by!(AuditEntry, action: "login_rate_limited", target_id: "missing-ip-3")
    detail = Jason.decode!(audit.detail)
    assert detail["reason"] == "rate_limited"
    assert detail["ip"] == "127.0.0.42"
  end

  test "validate_session rejects expired, inactive, and disabled-user sessions" do
    {:ok, user} =
      Auth.create_user(%{
        username: "session-user",
        display_name: "Session User",
        role: "viewer",
        password: "long-enough-password"
      })

    {:ok, _user, token} = Auth.create_session(user)
    session = Repo.get_by!(Session, token_hash: Auth.token_hash(token))

    session
    |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -1, :second))
    |> Repo.update!()

    assert {:error, :expired} = Auth.validate_session(token)
    refute Repo.get_by(Session, token_hash: Auth.token_hash(token))

    {:ok, _user, token} = Auth.create_session(user)
    session = Repo.get_by!(Session, token_hash: Auth.token_hash(token))

    session
    |> Ecto.Changeset.change(last_active_at: DateTime.add(DateTime.utc_now(), -31 * 60, :second))
    |> Repo.update!()

    assert {:error, :expired} = Auth.validate_session(token)

    {:ok, _user, token} = Auth.create_session(user)

    user
    |> User.update_changeset(%{active: false, role: user.role})
    |> Repo.update!()

    assert {:error, :invalid} = Auth.validate_session(token)
  end

  test "invalidate_user_sessions and prune_expired_sessions remove only matching sessions" do
    {:ok, user_a} = create_user!("session-a")
    {:ok, user_b} = create_user!("session-b")
    {:ok, _user, token_a} = Auth.create_session(user_a)
    {:ok, _user, token_b} = Auth.create_session(user_b)
    {:ok, _user, token_c} = Auth.create_session(user_b)
    {:ok, _user, token_d} = Auth.create_session(user_b)

    assert :ok = Auth.invalidate_user_sessions(user_a.id)
    refute Repo.get_by(Session, token_hash: Auth.token_hash(token_a))
    assert Repo.get_by(Session, token_hash: Auth.token_hash(token_b))

    Repo.get_by!(Session, token_hash: Auth.token_hash(token_b))
    |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -1, :second))
    |> Repo.update!()

    Repo.get_by!(Session, token_hash: Auth.token_hash(token_c))
    |> Ecto.Changeset.change(last_active_at: DateTime.add(DateTime.utc_now(), -31 * 60, :second))
    |> Repo.update!()

    assert {2, nil} = Auth.prune_expired_sessions()
    refute Repo.get_by(Session, token_hash: Auth.token_hash(token_b))
    refute Repo.get_by(Session, token_hash: Auth.token_hash(token_c))
    assert Repo.get_by(Session, token_hash: Auth.token_hash(token_d))
  end

  test "session pruner runs expired session cleanup on schedule" do
    {:ok, user} = create_user!("session-pruner")
    {:ok, _user, token} = Auth.create_session(user)

    Repo.get_by!(Session, token_hash: Auth.token_hash(token))
    |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -1, :second))
    |> Repo.update!()

    start_supervised!({
      SessionPruner,
      interval_ms: 10, name: :"session_pruner_#{System.unique_integer([:positive])}"
    })

    wait_until(fn ->
      Repo.get_by(Session, token_hash: Auth.token_hash(token)) == nil
    end)
  end

  test "update_user records role changes without exposing password data" do
    {:ok, actor} = create_user!("actor-user", "platform-admin")
    {:ok, user} = create_user!("editable-user")

    assert {:ok, %User{role: "analyst"} = updated} =
             Auth.update_user(user, %{role: "analyst"}, actor)

    audit = Repo.get_by!(AuditEntry, action: "role_changed", target_id: updated.id)
    assert audit.actor == actor.username
    assert audit.actor_type == "user"
    assert audit.result == "success"

    detail = Jason.decode!(audit.detail)
    assert detail["old"]["role"] == "viewer"
    assert detail["new"]["role"] == "analyst"
    refute audit.detail =~ "long-enough-password"
  end

  test "disable_user invalidates sessions and records an audit entry" do
    {:ok, actor} = create_user!("disable-actor", "platform-admin")
    {:ok, user} = create_user!("disable-target")
    {:ok, _user, token} = Auth.create_session(user)

    assert {:ok, %User{active: false} = disabled} = Auth.disable_user(user, actor)

    refute Repo.get_by(Session, token_hash: Auth.token_hash(token))

    audit = Repo.get_by!(AuditEntry, action: "user_disabled", target_id: disabled.id)
    assert audit.actor == actor.username
    assert Jason.decode!(audit.detail)["invalidated_session_count"] == 1
  end

  test "disable_user invalidates every session and causes owned tokens to be rejected" do
    {:ok, actor} = create_user!("bulk-disable-actor", "platform-admin")
    {:ok, user} = create_user!("bulk-disable-target")

    raw_sessions =
      for _ <- 1..3 do
        {:ok, _user, raw_session} = Auth.create_session(user)
        raw_session
      end

    raw_tokens =
      for index <- 1..2 do
        {:ok, _token, raw_token} =
          Auth.create_api_token(
            user,
            %{name: "owned-token-#{index}", permissions: ["sensors:view"]},
            actor
          )

        raw_token
      end

    assert {:ok, %User{active: false}} = Auth.disable_user(user, actor)

    for raw_session <- raw_sessions do
      refute Repo.get_by(Session, token_hash: Auth.token_hash(raw_session))
    end

    for raw_token <- raw_tokens do
      assert {:error, :invalid} = Auth.authenticate_api_token(raw_token)
    end
  end

  test "enable_user reactivates disabled accounts and records audit" do
    {:ok, actor} = create_user!("enable-actor", "platform-admin")
    {:ok, user} = create_user!("enable-target")
    {:ok, disabled} = Auth.disable_user(user, actor)

    assert {:ok, %User{active: true} = enabled} = Auth.enable_user(disabled, actor)

    audit = Repo.get_by!(AuditEntry, action: "user_enabled", target_id: enabled.id)
    assert audit.actor == actor.username
  end

  test "delete_user invalidates sessions, removes tokens, and records audit counts" do
    {:ok, actor} = create_user!("delete-actor", "platform-admin")
    {:ok, user} = create_user!("delete-target")
    {:ok, _user, token} = Auth.create_session(user)

    api_token =
      Repo.insert!(
        ApiToken.changeset(%ApiToken{}, %{
          name: "delete-token",
          token_hash: Auth.token_hash("raw-delete-token"),
          user_id: user.id,
          permissions: Jason.encode!(["sensors:view"])
        })
      )

    assert {:ok, %User{id: deleted_id}} = Auth.delete_user(user, actor)

    refute Repo.get(User, deleted_id)
    refute Repo.get_by(Session, token_hash: Auth.token_hash(token))
    refute Repo.get(ApiToken, api_token.id)

    audit = Repo.get_by!(AuditEntry, action: "user_deleted", target_id: deleted_id)
    detail = Jason.decode!(audit.detail)
    assert detail["invalidated_session_count"] == 1
    assert detail["revoked_token_count"] == 1
  end

  test "change_password verifies the current password and clears forced change flag" do
    {:ok, user} =
      Auth.create_user(%{
        username: "password-target",
        display_name: "Password Target",
        role: "viewer",
        must_change_password: true,
        password: "old-password-long"
      })

    assert {:error, :invalid_current_password} =
             Auth.change_password(user, "wrong-password", "new-password-long", user)

    assert {:ok, %User{must_change_password: false} = updated} =
             Auth.change_password(user, "old-password-long", "new-password-long", user)

    assert {:error, :invalid_credentials} = Auth.authenticate(user.username, "old-password-long")

    assert {:ok, %User{id: user_id}, _token} =
             Auth.authenticate(user.username, "new-password-long")

    assert user_id == updated.id

    entries = Repo.all(from(a in AuditEntry, where: a.target_id == ^user.id))
    assert Enum.any?(entries, &(&1.action == "password_change_failed"))
    assert Enum.any?(entries, &(&1.action == "password_changed"))
    refute Enum.any?(entries, &String.contains?(&1.detail || "", "new-password-long"))
  end

  test "admin_reset_password invalidates sessions and returns the temporary password once" do
    {:ok, actor} = create_user!("reset-actor", "platform-admin")
    {:ok, user} = create_user!("reset-target")
    {:ok, _user, token} = Auth.create_session(user)

    assert {:ok, %User{must_change_password: true} = updated, "temporary-password-long"} =
             Auth.admin_reset_password(user, "temporary-password-long", actor)

    refute Repo.get_by(Session, token_hash: Auth.token_hash(token))

    assert {:ok, %User{id: user_id}, _token} =
             Auth.authenticate(user.username, "temporary-password-long")

    assert user_id == updated.id

    audit = Repo.get_by!(AuditEntry, action: "password_reset", target_id: user.id)
    assert Jason.decode!(audit.detail)["invalidated_session_count"] == 1
    refute audit.detail =~ "temporary-password-long"
  end

  defp create_user!(username, role \\ "viewer") do
    Auth.create_user(%{
      username: username,
      display_name: username,
      role: role,
      password: "long-enough-password"
    })
  end

  defp restore_env(key, nil), do: System.delete_env(key)
  defp restore_env(key, value), do: System.put_env(key, value)

  defp wait_until(fun, attempts_left \\ 20)

  defp wait_until(fun, attempts_left) when attempts_left > 0 do
    if fun.() do
      :ok
    else
      Process.sleep(25)
      wait_until(fun, attempts_left - 1)
    end
  end

  defp wait_until(_fun, 0), do: flunk("condition was not met before timeout")
end
