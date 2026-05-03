defmodule ConfigManagerWeb.SessionController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.{Audit, Auth}

  def new(conn, _params) do
    html(conn, login_html(conn))
  end

  def create(conn, %{"username" => username, "password" => password}) do
    case Auth.authenticate(username, password) do
      {:ok, user, session_token} ->
        Audit.log(%{
          actor: user.username,
          actor_type: "user",
          action: "login",
          target_type: "user",
          target_id: user.id,
          result: "success"
        })

        conn
        |> configure_session(renew: true)
        |> put_session(:session_token, session_token)
        |> redirect(to: "/")

      {:error, _reason} ->
        Audit.log(%{
          actor: username || "unknown",
          actor_type: "anonymous",
          action: "login_failed",
          target_type: "user",
          target_id: username || "unknown",
          result: "failure"
        })

        conn
        |> put_flash(:error, "Invalid username or password")
        |> html(login_html(conn))
    end
  end

  def create(conn, _params) do
    conn
    |> put_flash(:error, "Invalid username or password")
    |> html(login_html(conn))
  end

  def delete(conn, _params) do
    token = get_session(conn, :session_token)
    user = conn.assigns[:current_user]
    Auth.destroy_session(token)

    if user do
      Audit.log(%{
        actor: user.username,
        actor_type: "user",
        action: "logout",
        target_type: "user",
        target_id: user.id,
        result: "success"
      })
    end

    conn
    |> configure_session(drop: true)
    |> redirect(to: "/login")
  end

  defp login_html(conn) do
    error =
      case Phoenix.Flash.get(conn.assigns[:flash] || %{}, :error) do
        nil -> nil
        message -> message |> Phoenix.HTML.html_escape() |> Phoenix.HTML.safe_to_string()
      end

    """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>RavenWire Login</title>
      </head>
      <body class="bg-gray-50">
        <main class="mx-auto max-w-md px-6 py-16">
          <h1 class="mb-6 text-2xl font-bold text-gray-900">RavenWire Manager</h1>
          #{if error, do: ~s(<div class="mb-4 rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">#{error}</div>), else: ""}
          <form action="/login" method="post" class="space-y-4 rounded border border-gray-200 bg-white p-6 shadow-sm">
            <input type="hidden" name="_csrf_token" value="#{Plug.CSRFProtection.get_csrf_token()}">
            <div>
              <label class="mb-1 block text-sm font-medium text-gray-700" for="username">Username</label>
              <input class="w-full rounded border border-gray-300 px-3 py-2" id="username" name="username" type="text" autocomplete="username" required>
            </div>
            <div>
              <label class="mb-1 block text-sm font-medium text-gray-700" for="password">Password</label>
              <input class="w-full rounded border border-gray-300 px-3 py-2" id="password" name="password" type="password" autocomplete="current-password" required>
            </div>
            <button class="w-full rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700" type="submit">Log in</button>
          </form>
        </main>
      </body>
    </html>
    """
  end
end
