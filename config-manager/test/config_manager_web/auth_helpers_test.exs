defmodule ConfigManagerWeb.AuthHelpersTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Auth
  alias ConfigManagerWeb.AuthHelpers

  test "authorize allows users with permission and rejects missing permission" do
    {:ok, admin} =
      Auth.create_user(%{
        username: "auth-helper-admin",
        display_name: "Admin",
        role: "platform-admin",
        password: "long-enough-password"
      })

    {:ok, viewer} =
      Auth.create_user(%{
        username: "auth-helper-viewer",
        display_name: "Viewer",
        role: "viewer",
        password: "long-enough-password"
      })

    assert :ok = AuthHelpers.authorize(%{assigns: %{current_user: admin}}, "system:manage")

    assert {:error, :forbidden} =
             AuthHelpers.authorize(%{assigns: %{current_user: viewer}}, "system:manage")

    assert {:error, :forbidden} =
             AuthHelpers.authorize(%{assigns: %{current_user: nil}}, "dashboard:view")
  end
end
