defmodule ConfigManager.Auth.SchemaTest do
  use ConfigManager.DataCase, async: false

  alias Ecto.Adapters.SQL
  alias ConfigManager.Auth.{ApiToken, Session, User}

  test "auth migrations create required tables, columns, and indexes" do
    assert_table_columns(
      "users",
      ~w(id username password_hash display_name role active must_change_password inserted_at updated_at)
    )

    assert_table_columns(
      "sessions",
      ~w(id user_id token_hash last_active_at expires_at inserted_at)
    )

    assert_table_columns(
      "api_tokens",
      ~w(id name token_hash user_id permissions expires_at revoked_at inserted_at updated_at)
    )

    assert_table_columns(
      "audit_log",
      ~w(id timestamp actor actor_type action target_type target_id result detail)
    )

    assert_index("users", ["username"], unique?: true)
    assert_index("users", ["role"])
    assert_index("sessions", ["user_id"])
    assert_index("sessions", ["token_hash"], unique?: true)
    assert_index("sessions", ["expires_at"])
    assert_index("api_tokens", ["user_id"])
    assert_index("api_tokens", ["token_hash"], unique?: true)
  end

  test "user create changeset validates role, password policy, and username normalization" do
    changeset =
      User.create_changeset(%User{}, %{
        username: "  Operator  ",
        role: "sensor-operator",
        password: "long-enough-password"
      })

    assert changeset.valid?
    assert Ecto.Changeset.get_change(changeset, :username) == "operator"
    assert Ecto.Changeset.get_change(changeset, :password_hash)
    refute Ecto.Changeset.get_change(changeset, :password)

    invalid =
      User.create_changeset(%User{}, %{
        username: "bad",
        role: "space-captain",
        password: "bad"
      })

    refute invalid.valid?
    assert %{role: [_], password: [_]} = errors_on(invalid)
  end

  test "user update changeset does not accept password changes" do
    user = %User{role: "viewer"}

    changeset =
      User.update_changeset(user, %{
        role: "analyst",
        display_name: "Analyst",
        password: "new-password-that-should-not-be-cast"
      })

    assert changeset.valid?
    assert Ecto.Changeset.get_change(changeset, :role) == "analyst"
    refute Map.has_key?(changeset.changes, :password)
    refute Map.has_key?(changeset.changes, :password_hash)
  end

  test "session changeset requires hashed token and timestamps" do
    valid =
      Session.changeset(%Session{}, %{
        user_id: Ecto.UUID.generate(),
        token_hash: String.duplicate("a", 64),
        last_active_at: DateTime.utc_now(),
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
      })

    assert valid.valid?

    invalid = Session.changeset(%Session{}, %{})
    refute invalid.valid?

    assert %{user_id: [_], token_hash: [_], last_active_at: [_], expires_at: [_]} =
             errors_on(invalid)
  end

  test "api token changeset requires owner, hash, name, and permission payload" do
    valid =
      ApiToken.changeset(%ApiToken{}, %{
        name: "automation",
        token_hash: String.duplicate("b", 64),
        user_id: Ecto.UUID.generate(),
        permissions: Jason.encode!(["sensors:view"])
      })

    assert valid.valid?

    invalid = ApiToken.changeset(%ApiToken{}, %{})
    refute invalid.valid?
    assert %{name: [_], token_hash: [_], user_id: [_]} = errors_on(invalid)
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp assert_table_columns(table, expected_columns) do
    columns =
      SQL.query!(Repo, "PRAGMA table_info(#{table})", [])
      |> Map.fetch!(:rows)
      |> Enum.map(fn [_cid, name, _type, _notnull, _default, _pk] -> name end)

    for column <- expected_columns do
      assert column in columns
    end
  end

  defp assert_index(table, expected_columns, opts \\ []) do
    unique? = Keyword.get(opts, :unique?, false)

    indexes =
      SQL.query!(Repo, "PRAGMA index_list(#{table})", [])
      |> Map.fetch!(:rows)
      |> Enum.map(fn [_seq, name, unique, _origin, _partial] ->
        columns =
          SQL.query!(Repo, "PRAGMA index_info(#{name})", [])
          |> Map.fetch!(:rows)
          |> Enum.map(fn [_seqno, _cid, column_name] -> column_name end)

        {columns, unique == 1}
      end)

    assert Enum.any?(indexes, fn {columns, unique} ->
             columns == expected_columns and (not unique? or unique)
           end)
  end
end
