defmodule ConfigManager.Auth do
  @moduledoc "Local authentication, users, and server-side sessions."

  import Ecto.Query

  alias ConfigManager.Auth.{Password, Session, User}
  alias ConfigManager.Repo

  @session_token_bytes 32

  def list_users do
    Repo.all(from(u in User, order_by: [asc: u.username]))
  end

  def get_user!(id), do: Repo.get!(User, id)
  def get_user(id), do: Repo.get(User, id)

  def get_user_by_username(username),
    do: Repo.get_by(User, username: normalize_username(username))

  def create_user(attrs, _actor \\ nil) do
    %User{}
    |> User.create_changeset(attrs)
    |> Repo.insert()
  end

  def update_user(%User{} = user, attrs, _actor \\ nil) do
    user
    |> User.update_changeset(attrs)
    |> Repo.update()
  end

  def authenticate(username, password) do
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
end
