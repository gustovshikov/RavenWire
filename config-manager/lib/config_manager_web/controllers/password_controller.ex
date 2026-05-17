defmodule ConfigManagerWeb.PasswordController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Auth

  def edit(conn, _params) do
    html(conn, password_html(conn))
  end

  def update(conn, %{
        "current_password" => current_password,
        "password" => password
      }) do
    user = conn.assigns.current_user

    case Auth.change_password(user, current_password, password, user) do
      {:ok, _user} ->
        conn
        |> put_flash(:info, "Password changed.")
        |> redirect(to: "/")

      {:error, :invalid_current_password} ->
        conn
        |> put_flash(:error, "Current password is incorrect.")
        |> render_password()

      {:error, changeset} ->
        conn
        |> put_flash(:error, password_error(changeset))
        |> render_password()
    end
  end

  def update(conn, _params) do
    conn
    |> put_flash(:error, "Current password and new password are required.")
    |> render_password()
  end

  defp render_password(conn), do: html(conn, password_html(conn))

  defp password_html(conn) do
    error = flash_message(conn, :error)
    info = flash_message(conn, :info)

    """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Change RavenWire Password</title>
        <link rel="stylesheet" href="/assets/app.css">
      </head>
      <body class="bg-gray-50">
        <main class="mx-auto max-w-md px-6 py-16">
          <div class="mb-6 text-center">
            <img class="mx-auto mb-4 w-full max-w-sm" src="/images/logos/main-logo-transparent.png" alt="RavenWire">
            <h1 class="text-2xl font-bold text-gray-900">Change Password</h1>
          </div>
          #{if error, do: ~s(<div class="mb-4 rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">#{error}</div>), else: ""}
          #{if info, do: ~s(<div class="mb-4 rounded border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700">#{info}</div>), else: ""}
          <form action="/password/change" method="post" class="space-y-4 rounded border border-gray-200 bg-white p-6 shadow-sm">
            <input type="hidden" name="_csrf_token" value="#{Plug.CSRFProtection.get_csrf_token()}">
            <div>
              <label class="mb-1 block text-sm font-medium text-gray-700" for="current_password">Current password</label>
              <input class="w-full rounded border border-gray-300 px-3 py-2" id="current_password" name="current_password" type="password" autocomplete="current-password" required>
            </div>
            <div>
              <label class="mb-1 block text-sm font-medium text-gray-700" for="password">New password</label>
              <input class="w-full rounded border border-gray-300 px-3 py-2" id="password" name="password" type="password" autocomplete="new-password" required>
            </div>
            <button class="w-full rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700" type="submit">Change password</button>
          </form>
        </main>
      </body>
    </html>
    """
  end

  defp flash_message(conn, kind) do
    case Phoenix.Flash.get(conn.assigns[:flash] || %{}, kind) do
      nil -> nil
      message -> message |> Phoenix.HTML.html_escape() |> Phoenix.HTML.safe_to_string()
    end
  end

  defp password_error(changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Map.get(:password, ["Could not change password."])
    |> List.first()
  end
end
