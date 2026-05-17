defmodule ConfigManager.Auth do
  @moduledoc "Local authentication, users, and server-side sessions."

  import Ecto.Query

  alias ConfigManager.Auth.{ApiToken, Password, RateLimiter, Session, User}
  alias ConfigManager.{Audit, Repo}
  alias Ecto.Multi

  @session_token_bytes 32
  @api_token_bytes 32

  def list_users do
    Repo.all(from(u in User, order_by: [asc: u.username]))
  end

  def list_api_tokens do
    ApiToken
    |> order_by([t], desc: t.inserted_at)
    |> preload(:user)
    |> Repo.all()
    |> Enum.map(&redact_api_token/1)
  end

  def get_api_token!(id) do
    ApiToken
    |> Repo.get!(id)
    |> Repo.preload(:user)
    |> redact_api_token()
  end

  def get_user!(id), do: Repo.get!(User, id)
  def get_user(id), do: Repo.get(User, id)

  def get_user_by_username(username),
    do: Repo.get_by(User, username: normalize_username(username))

  def create_user(attrs, actor \\ nil) do
    actor = normalize_actor(actor)

    %User{}
    |> User.create_changeset(attrs)
    |> then(fn changeset ->
      Multi.new()
      |> Multi.insert(:user, changeset)
      |> Audit.append_multi(fn %{user: user} ->
        audit_attrs(actor, "user_created", user, "success", %{
          username: user.username,
          role: user.role,
          active: user.active,
          must_change_password: user.must_change_password
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{user: user}} -> {:ok, user}
        {:error, :user, changeset, _changes} -> {:error, changeset}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end)
  end

  def update_user(%User{} = user, attrs, actor \\ nil) do
    actor = normalize_actor(actor)
    before = user_snapshot(user)

    Multi.new()
    |> Multi.update(:user, User.update_changeset(user, attrs))
    |> maybe_invalidate_sessions_on_disable(user, attrs)
    |> Audit.append_multi(fn %{user: updated} ->
      audit_attrs(actor, update_action(before, updated), updated, "success", %{
        old: before,
        new: user_snapshot(updated)
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{user: updated}} -> {:ok, updated}
      {:error, :user, changeset, _changes} -> {:error, changeset}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  def disable_user(%User{} = user, actor \\ nil) do
    actor = normalize_actor(actor)

    Multi.new()
    |> Multi.update(:user, User.update_changeset(user, %{active: false}))
    |> Multi.delete_all(:sessions, from(s in Session, where: s.user_id == ^user.id))
    |> Audit.append_multi(fn %{sessions: {session_count, _}, user: updated} ->
      audit_attrs(actor, "user_disabled", updated, "success", %{
        username: updated.username,
        invalidated_session_count: session_count
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{user: updated}} -> {:ok, updated}
      {:error, :user, changeset, _changes} -> {:error, changeset}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  def enable_user(%User{} = user, actor \\ nil) do
    actor = normalize_actor(actor)

    Multi.new()
    |> Multi.update(:user, User.update_changeset(user, %{active: true}))
    |> Audit.append_multi(fn %{user: updated} ->
      audit_attrs(actor, "user_enabled", updated, "success", %{username: updated.username})
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{user: updated}} -> {:ok, updated}
      {:error, :user, changeset, _changes} -> {:error, changeset}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  def delete_user(%User{} = user, actor \\ nil) do
    actor = normalize_actor(actor)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    updated_at = now |> DateTime.to_naive() |> NaiveDateTime.truncate(:second)

    Multi.new()
    |> Multi.delete_all(:sessions, from(s in Session, where: s.user_id == ^user.id))
    |> Multi.update_all(:tokens, from(t in ApiToken, where: t.user_id == ^user.id),
      set: [revoked_at: now, updated_at: updated_at]
    )
    |> Multi.delete(:user, user)
    |> Audit.append_multi(fn %{sessions: {session_count, _}, tokens: {token_count, _}} ->
      audit_attrs(actor, "user_deleted", user, "success", %{
        username: user.username,
        invalidated_session_count: session_count,
        revoked_token_count: token_count
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{user: deleted}} -> {:ok, deleted}
      {:error, :user, changeset, _changes} -> {:error, changeset}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  def change_password(%User{} = user, current_password, new_password, actor \\ nil) do
    actor = normalize_actor(actor || user)

    if Password.verify_password(current_password, user.password_hash) do
      Multi.new()
      |> Multi.update(
        :user,
        User.password_changeset(user, %{password: new_password, must_change_password: false})
      )
      |> Audit.append_multi(fn %{user: updated} ->
        audit_attrs(actor, "password_changed", updated, "success", %{username: updated.username})
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{user: updated}} -> {:ok, updated}
        {:error, :user, changeset, _changes} -> {:error, changeset}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    else
      Audit.log(
        audit_attrs(actor, "password_change_failed", user, "failure", %{
          reason: "invalid_current_password"
        })
      )

      {:error, :invalid_current_password}
    end
  end

  def admin_reset_password(%User{} = user, new_password, actor) do
    actor = normalize_actor(actor)
    password = new_password || Password.generate_random_password()

    Multi.new()
    |> Multi.update(
      :user,
      User.password_changeset(user, %{password: password, must_change_password: true})
    )
    |> Multi.delete_all(:sessions, from(s in Session, where: s.user_id == ^user.id))
    |> Audit.append_multi(fn %{sessions: {session_count, _}, user: updated} ->
      audit_attrs(actor, "password_reset", updated, "success", %{
        username: updated.username,
        invalidated_session_count: session_count
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{user: updated}} -> {:ok, updated, password}
      {:error, :user, changeset, _changes} -> {:error, changeset}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  def create_api_token(%User{} = user, attrs, actor \\ nil) do
    actor = normalize_actor(actor || user)

    with {:ok, permissions} <- normalize_api_token_permissions(get_attr(attrs, :permissions, [])) do
      raw_token = random_api_token()

      token_attrs = %{
        name: get_attr(attrs, :name),
        token_hash: token_hash(raw_token),
        user_id: user.id,
        permissions: Jason.encode!(permissions),
        expires_at: get_attr(attrs, :expires_at)
      }

      Multi.new()
      |> Multi.insert(:api_token, ApiToken.changeset(%ApiToken{}, token_attrs))
      |> Audit.append_multi(fn %{api_token: token} ->
        api_token_audit_attrs(actor, "api_token_created", token, "success", %{
          name: token.name,
          permissions: permissions,
          expires_at: token.expires_at,
          created_by: user.username
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{api_token: token}} -> {:ok, redact_api_token(token), raw_token}
        {:error, :api_token, changeset, _changes} -> {:error, changeset}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  def revoke_api_token(%ApiToken{id: id}, actor \\ nil) do
    actor = normalize_actor(actor)
    token = Repo.get!(ApiToken, id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Multi.new()
    |> Multi.update(:api_token, Ecto.Changeset.change(token, revoked_at: now))
    |> Audit.append_multi(fn %{api_token: revoked} ->
      api_token_audit_attrs(actor, "api_token_revoked", revoked, "success", %{
        name: revoked.name,
        revoked_at: revoked.revoked_at
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{api_token: revoked}} -> {:ok, redact_api_token(revoked)}
      {:error, :api_token, changeset, _changes} -> {:error, changeset}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  def authenticate_api_token(raw_token) when is_binary(raw_token) do
    case Repo.get_by(ApiToken, token_hash: token_hash(raw_token)) |> Repo.preload(:user) do
      nil ->
        {:error, :invalid}

      %ApiToken{} = token ->
        cond do
          token.revoked_at != nil ->
            {:error, :invalid}

          token.expires_at != nil and
              DateTime.compare(token.expires_at, DateTime.utc_now()) != :gt ->
            {:error, :invalid}

          token.user == nil or not token.user.active ->
            {:error, :invalid}

          true ->
            {:ok, redact_api_token(token)}
        end
    end
  end

  def authenticate_api_token(_raw_token), do: {:error, :invalid}

  def authenticate(username, password, opts \\ []) do
    ip = Keyword.get(opts, :ip)

    case check_login_rate_limits(username, ip) do
      :ok ->
        username
        |> authenticate_without_rate_limit(password)
        |> handle_auth_result(username, ip)

      {:error, reason} ->
        log_rate_limit(username, ip, reason)
        {:error, :invalid_credentials}
    end
  end

  defp authenticate_without_rate_limit(username, password) do
    user = get_user_by_username(username)

    cond do
      user == nil ->
        Password.verify_password(password, nil)
        {:error, :invalid_credentials}

      not user.active ->
        Password.verify_password(password, user.password_hash)
        {:error, :invalid_credentials}

      Password.verify_password(password, user.password_hash) ->
        create_session(user)

      true ->
        {:error, :invalid_credentials}
    end
  end

  def create_session(%User{} = user) do
    now = DateTime.utc_now()
    raw_token = random_token()

    attrs = %{
      user_id: user.id,
      token_hash: token_hash(raw_token),
      last_active_at: now,
      expires_at: DateTime.add(now, max_session_lifetime_seconds(), :second)
    }

    case %Session{} |> Session.changeset(attrs) |> Repo.insert() do
      {:ok, _session} -> {:ok, user, raw_token}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def validate_session(nil), do: {:error, :missing}

  def validate_session(raw_token) when is_binary(raw_token) do
    now = DateTime.utc_now()

    case Repo.get_by(Session, token_hash: token_hash(raw_token)) |> Repo.preload(:user) do
      nil ->
        {:error, :missing}

      %Session{} = session ->
        cond do
          DateTime.compare(session.expires_at, now) != :gt ->
            destroy_session(raw_token)
            {:error, :expired}

          DateTime.diff(now, session.last_active_at, :second) > inactivity_timeout_seconds() ->
            destroy_session(raw_token)
            {:error, :expired}

          session.user == nil or not session.user.active ->
            destroy_session(raw_token)
            {:error, :invalid}

          true ->
            session |> Session.touch_changeset(now) |> Repo.update()
            {:ok, session.user}
        end
    end
  end

  def destroy_session(nil), do: :ok

  def destroy_session(raw_token) do
    Repo.delete_all(from(s in Session, where: s.token_hash == ^token_hash(raw_token)))
    :ok
  end

  def invalidate_user_sessions(user_id) do
    Repo.delete_all(from(s in Session, where: s.user_id == ^user_id))
    :ok
  end

  def prune_expired_sessions do
    now = DateTime.utc_now()
    Repo.delete_all(from(s in Session, where: s.expires_at <= ^now))
  end

  def token_hash(raw_token) when is_binary(raw_token) do
    :crypto.hash(:sha256, raw_token) |> Base.encode16(case: :lower)
  end

  defp random_token do
    @session_token_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp random_api_token do
    @api_token_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp normalize_username(username) do
    username |> to_string() |> String.trim() |> String.downcase()
  end

  defp inactivity_timeout_seconds do
    "RAVENWIRE_SESSION_TIMEOUT_MIN"
    |> System.get_env("30")
    |> parse_positive_int(30)
    |> Kernel.*(60)
  end

  defp max_session_lifetime_seconds do
    "RAVENWIRE_SESSION_MAX_LIFETIME_HR"
    |> System.get_env("24")
    |> parse_positive_int(24)
    |> Kernel.*(3_600)
  end

  defp parse_positive_int(value, default) do
    case Integer.parse(to_string(value)) do
      {int, _} when int > 0 -> int
      _ -> default
    end
  end

  defp check_login_rate_limits(username, ip) do
    with :ok <- RateLimiter.check_username(username),
         :ok <- RateLimiter.check_ip(ip) do
      :ok
    else
      {:error, :rate_limited} -> {:error, :rate_limited}
      {:error, :unavailable} -> {:error, :rate_limiter_unavailable}
    end
  end

  defp handle_auth_result({:ok, _user, _token} = result, username, ip) do
    RateLimiter.clear_username(username)
    RateLimiter.clear_ip(ip)
    result
  end

  defp handle_auth_result({:error, :invalid_credentials} = result, username, ip) do
    RateLimiter.record_failure(username)
    RateLimiter.record_ip_failure(ip)
    result
  end

  defp log_rate_limit(username, ip, reason) do
    Audit.log(%{
      actor: normalize_username(username),
      actor_type: "anonymous",
      action: "login_rate_limited",
      target_type: "user",
      target_id: normalize_username(username),
      result: "failure",
      detail: %{reason: reason, ip: format_ip(ip)}
    })
  end

  defp maybe_invalidate_sessions_on_disable(%Multi{} = multi, %User{active: true} = user, attrs) do
    if Map.get(attrs, :active, Map.get(attrs, "active")) == false do
      Multi.delete_all(multi, :sessions, from(s in Session, where: s.user_id == ^user.id))
    else
      multi
    end
  end

  defp maybe_invalidate_sessions_on_disable(%Multi{} = multi, _user, _attrs), do: multi

  defp update_action(%{role: old_role}, %{role: new_role}) when old_role != new_role,
    do: "role_changed"

  defp update_action(%{active: true}, %{active: false}), do: "user_disabled"
  defp update_action(%{active: false}, %{active: true}), do: "user_enabled"
  defp update_action(_old, _new), do: "user_updated"

  defp user_snapshot(%User{} = user) do
    %{
      display_name: user.display_name,
      role: user.role,
      active: user.active,
      must_change_password: user.must_change_password
    }
  end

  defp audit_attrs(actor, action, %User{} = target, result, detail) do
    %{
      actor: actor.name,
      actor_type: actor.type,
      action: action,
      target_type: "user",
      target_id: target.id,
      result: result,
      detail: detail
    }
  end

  defp api_token_audit_attrs(actor, action, %ApiToken{} = target, result, detail) do
    %{
      actor: actor.name,
      actor_type: actor.type,
      action: action,
      target_type: "api_token",
      target_id: target.id,
      result: result,
      detail: detail
    }
  end

  defp normalize_actor(%User{username: username}), do: %{name: username, type: "user"}
  defp normalize_actor(%ApiToken{name: name}), do: %{name: name, type: "api_token"}
  defp normalize_actor(%{username: username}), do: %{name: username, type: "user"}
  defp normalize_actor(actor) when is_binary(actor), do: %{name: actor, type: "user"}
  defp normalize_actor(_actor), do: %{name: "system", type: "system"}

  defp format_ip(nil), do: nil
  defp format_ip(ip) when is_tuple(ip), do: ip |> Tuple.to_list() |> Enum.join(".")
  defp format_ip(ip), do: to_string(ip)

  defp redact_api_token(%ApiToken{} = token), do: %{token | token_hash: nil}

  defp normalize_api_token_permissions(permissions) do
    case ApiToken.encode_permissions(permissions) do
      {:ok, json} -> {:ok, ApiToken.permissions_list(json)}
      {:error, reason} -> {:error, api_token_permissions_changeset(reason)}
    end
  end

  defp api_token_permissions_changeset(reason) do
    %ApiToken{}
    |> ApiToken.changeset(%{
      name: "",
      token_hash: String.duplicate("0", 64),
      user_id: Ecto.UUID.generate(),
      permissions: "[]"
    })
    |> Ecto.Changeset.add_error(:permissions, reason)
  end

  defp get_attr(attrs, key, default \\ nil) do
    Map.get(attrs, key, Map.get(attrs, to_string(key), default))
  end
end
