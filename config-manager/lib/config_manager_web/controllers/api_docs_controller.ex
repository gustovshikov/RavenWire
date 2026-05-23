defmodule ConfigManagerWeb.ApiDocsController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Auth

  def index(conn, _params) do
    if docs_auth_required?() do
      case Auth.validate_session(get_session(conn, :session_token)) do
        {:ok, _user} -> render_docs(conn)
        {:error, _reason} -> redirect(conn, to: "/login")
      end
    else
      render_docs(conn)
    end
  end

  defp render_docs(conn) do
    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, docs_html())
  end

  defp docs_auth_required? do
    Application.get_env(:config_manager, :api_docs_require_auth, false)
  end

  defp docs_html do
    """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>RavenWire Config Manager API</title>
      <style>
        :root {
          color-scheme: dark;
          --bg: #070b11;
          --panel: #141922;
          --line: #29313d;
          --text: #e5e7eb;
          --muted: #9ca3af;
          --accent: #38bdf8;
          --method: #22c55e;
        }

        body {
          margin: 0;
          background: var(--bg);
          color: var(--text);
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }

        main {
          max-width: 1180px;
          margin: 0 auto;
          padding: 32px 24px 56px;
        }

        header {
          border-bottom: 1px solid var(--line);
          margin-bottom: 24px;
          padding-bottom: 18px;
        }

        h1 {
          margin: 0 0 8px;
          font-size: 30px;
          line-height: 1.15;
        }

        p {
          color: var(--muted);
          line-height: 1.55;
          margin: 0;
        }

        a {
          color: var(--accent);
        }

        .toolbar {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          align-items: center;
          margin: 22px 0;
        }

        input,
        textarea {
          min-width: min(460px, 100%);
          flex: 1;
          border: 1px solid var(--line);
          background: #0b1018;
          color: var(--text);
          border-radius: 6px;
          padding: 10px 12px;
          font: inherit;
        }

        textarea {
          box-sizing: border-box;
          display: block;
          min-height: 110px;
          min-width: 100%;
          resize: vertical;
          margin-top: 10px;
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        }

        button {
          border: 0;
          background: var(--accent);
          color: #051016;
          border-radius: 6px;
          padding: 9px 12px;
          font: inherit;
          font-weight: 700;
          cursor: pointer;
        }

        .try-row {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          gap: 10px;
          align-items: center;
          margin-top: 14px;
        }

        .response-title {
          margin-top: 14px;
          color: var(--muted);
          font-size: 13px;
          text-transform: uppercase;
        }

        .endpoint {
          border: 1px solid var(--line);
          background: var(--panel);
          border-radius: 8px;
          margin-bottom: 12px;
          padding: 14px 16px;
        }

        .endpoint summary {
          cursor: pointer;
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          align-items: baseline;
        }

        .method {
          color: var(--method);
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          font-weight: 700;
          min-width: 48px;
          text-transform: uppercase;
        }

        .path {
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        }

        .permission {
          color: var(--muted);
          font-size: 13px;
        }

        pre {
          overflow-x: auto;
          border: 1px solid var(--line);
          background: #090d14;
          border-radius: 6px;
          padding: 12px;
        }
      </style>
    </head>
    <body>
      <main>
        <header>
          <h1>RavenWire Config Manager API</h1>
          <p>Bearer-token Public API documentation for implemented `/api/v1` workflows. Sensor Agent bootstrap and mTLS control endpoints are intentionally not listed here.</p>
        </header>
        <p>OpenAPI JSON: <a href="/api/v1/openapi.json">/api/v1/openapi.json</a></p>
        <div class="toolbar">
          <input id="filter" type="search" placeholder="Filter endpoints by path, method, summary, or permission">
          <input id="token" type="password" autocomplete="off" placeholder="Bearer token for Try it out requests">
        </div>
        <section id="endpoint-list" aria-live="polite">Loading API spec...</section>
      </main>
      <script>
        const list = document.getElementById("endpoint-list");
        const filter = document.getElementById("filter");
        const token = document.getElementById("token");
        let endpoints = [];

        function escapeHtml(value) {
          return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;");
        }

        function render() {
          const query = filter.value.trim().toLowerCase();
          const visible = endpoints.filter((endpoint) => endpoint.search.includes(query));
          list.innerHTML = visible.map((endpoint) => `
            <details class="endpoint" data-index="${endpoint.index}">
              <summary>
                <span class="method">${escapeHtml(endpoint.method)}</span>
                <span class="path">${escapeHtml(endpoint.path)}</span>
                <span>${escapeHtml(endpoint.summary)}</span>
                <span class="permission">${escapeHtml(endpoint.permission)}</span>
              </summary>
              <p>${escapeHtml(endpoint.description)}</p>
              <div class="try-row">
                <input id="path-${endpoint.index}" value="${escapeHtml(endpoint.path)}" aria-label="Request path">
                <button type="button" data-try="${endpoint.index}">Try it out</button>
              </div>
              ${endpoint.method === "get" ? "" : `<textarea id="body-${endpoint.index}" aria-label="Request body">${escapeHtml(endpoint.requestExample)}</textarea>`}
              <div class="response-title">Responses</div>
              <pre>${escapeHtml(endpoint.responses)}</pre>
              <div class="response-title">Try it out result</div>
              <pre id="result-${endpoint.index}">No request sent.</pre>
            </details>
          `).join("") || "<p>No endpoints match the current filter.</p>";
        }

        async function tryEndpoint(index) {
          const endpoint = endpoints[index];
          const path = document.getElementById(`path-${index}`).value;
          const bodyInput = document.getElementById(`body-${index}`);
          const headers = { "accept": "application/json" };
          const rawToken = token.value.trim();
          const options = { method: endpoint.method.toUpperCase(), headers };
          const result = document.getElementById(`result-${index}`);

          if (rawToken) {
            headers.authorization = `Bearer ${rawToken}`;
          }

          if (bodyInput) {
            headers["content-type"] = "application/json";
            options.body = bodyInput.value.trim() || "{}";
          }

          result.textContent = "Sending request...";

          try {
            const response = await fetch(path, options);
            const text = await response.text();
            result.textContent = [
              `${response.status} ${response.statusText}`,
              `X-Request-ID: ${response.headers.get("x-request-id") || ""}`,
              "",
              text
            ].join("\\n");
          } catch (error) {
            result.textContent = error.message;
          }
        }

        fetch("/api/v1/openapi.json")
          .then((response) => response.json())
          .then((spec) => {
            endpoints = Object.entries(spec.paths).flatMap(([path, methods]) =>
              Object.entries(methods).map(([method, operation]) => {
                const media = operation.requestBody?.content?.["application/json"];

                return {
                path,
                method,
                summary: operation.summary || "",
                description: operation.description || "",
                permission: operation["x-ravenwire-permission"] || "public",
                responses: JSON.stringify(operation.responses || {}, null, 2),
                requestExample: JSON.stringify(media?.example || {}, null, 2)
              };
            })
            );
            endpoints.forEach((endpoint, index) => {
              endpoint.index = index;
              endpoint.search = [
                endpoint.path,
                endpoint.method,
                endpoint.summary,
                endpoint.description,
                endpoint.permission
              ].join(" ").toLowerCase();
            });
            render();
          })
          .catch((error) => {
            list.innerHTML = `<p>Unable to load /api/v1/openapi.json: ${error.message}</p>`;
          });

        filter.addEventListener("input", render);
        list.addEventListener("click", (event) => {
          const index = event.target.dataset.try;

          if (index !== undefined) {
            tryEndpoint(Number(index));
          }
        });
      </script>
    </body>
    </html>
    """
  end
end
