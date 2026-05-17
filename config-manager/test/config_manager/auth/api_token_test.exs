defmodule ConfigManager.Auth.ApiTokenTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.{AuditEntry, Auth, Repo}
  alias ConfigManager.Auth.{ApiToken, User}

  test "create_api_token stores only a hash and list_api_tokens redacts hashes" do
    {:ok, user} = create_user!("token-owner")

    assert {:ok, %ApiToken{} = token, raw_token} =
             Auth.create_api_token(
               user,
               %{
                 name: "splunk-workflow",
                 permissions: ["sensors:view", "pcap:search"]
               },
               user
             )

    assert is_binary(raw_token)
    assert byte_size(raw_token) >= 32
    assert token.token_hash == nil

    stored = Repo.get!(ApiToken, token.id)
    assert stored.token_hash == Auth.token_hash(raw_token)
    refute stored.token_hash =~ raw_token
    assert ApiToken.permissions_list(stored) == ["sensors:view", "pcap:search"]

    listed = Auth.list_api_tokens()
    assert Enum.any?(listed, &(&1.id == token.id and &1.token_hash == nil))
    refute inspect(listed) =~ stored.token_hash
    refute inspect(listed) =~ raw_token

    audit = Repo.get_by!(AuditEntry, action: "api_token_created", target_id: token.id)
    assert audit.actor == user.username
    refute audit.detail =~ raw_token
    refute audit.detail =~ stored.token_hash
  end

  test "create_api_token rejects empty or unknown permissions" do
    {:ok, user} = create_user!("token-scope-owner")

    assert {:error, changeset} =
             Auth.create_api_token(user, %{name: "empty", permissions: []}, user)

    assert %{permissions: [_ | _]} = errors_on(changeset)

    assert {:error, changeset} =
             Auth.create_api_token(user, %{name: "bad", permissions: ["space:walk"]}, user)

    assert %{permissions: [_ | _]} = errors_on(changeset)
  end

  test "authenticate_api_token accepts only the raw token value" do
    {:ok, user} = create_user!("auth-token-owner")
    {:ok, token, raw_token} = Auth.create_api_token(user, token_attrs(), user)

    assert {:ok, %ApiToken{id: token_id, token_hash: nil, user: %User{id: user_id}}} =
             Auth.authenticate_api_token(raw_token)

    assert token_id == token.id
    assert user_id == user.id
    assert {:error, :invalid} = Auth.authenticate_api_token("not-the-token")
  end

  test "expired, revoked, and disabled-user tokens are rejected" do
    {:ok, user} = create_user!("rejected-token-owner")

    {:ok, _expired, expired_raw} =
      Auth.create_api_token(
        user,
        Map.put(token_attrs(), :expires_at, DateTime.add(DateTime.utc_now(), -1, :second)),
        user
      )

    assert {:error, :invalid} = Auth.authenticate_api_token(expired_raw)

    {:ok, active, active_raw} = Auth.create_api_token(user, token_attrs("revoked-token"), user)

    assert {:ok, %ApiToken{revoked_at: revoked_at, token_hash: nil}} =
             Auth.revoke_api_token(active, user)

    assert revoked_at
    assert {:error, :invalid} = Auth.authenticate_api_token(active_raw)

    {:ok, disabled_user} = create_user!("disabled-token-owner")

    {:ok, _disabled_token, disabled_raw} =
      Auth.create_api_token(disabled_user, token_attrs(), user)

    {:ok, _disabled_user} = Auth.disable_user(disabled_user, user)

    assert {:error, :invalid} = Auth.authenticate_api_token(disabled_raw)
  end

  defp token_attrs(name \\ "automation") do
    %{name: name, permissions: ["sensors:view"]}
  end

  defp create_user!(username) do
    Auth.create_user(%{
      username: username,
      display_name: username,
      role: "platform-admin",
      password: "long-enough-password"
    })
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
