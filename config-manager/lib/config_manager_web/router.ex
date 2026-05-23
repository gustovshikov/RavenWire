defmodule ConfigManagerWeb.Router do
  use ConfigManagerWeb, :router

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_live_flash)
    plug(:put_root_layout, html: {ConfigManagerWeb.Layouts, :root})
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
  end

  pipeline :api do
    plug(:accepts, ["json"])
    plug(ConfigManagerWeb.Plugs.ApiVersionHeader)
  end

  pipeline :api_docs_json do
    plug(:accepts, ["json"])
    plug(:fetch_session)
    plug(ConfigManagerWeb.Plugs.ApiVersionHeader)
  end

  pipeline :api_token_auth do
    plug(ConfigManagerWeb.Plugs.ApiTokenAuth)
    plug(ConfigManagerWeb.Plugs.ApiRequestAudit)
    plug(ConfigManagerWeb.Plugs.ApiRateLimit)
  end

  pipeline :require_auth do
    plug(ConfigManagerWeb.Plugs.RequireAuth)
  end

  pipeline :require_password_change do
    plug(ConfigManagerWeb.Plugs.RequirePasswordChange)
  end

  pipeline :dashboard_view do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "dashboard:view")
  end

  pipeline :sensors_view do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "sensors:view")
  end

  pipeline :enrollment_manage do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "enrollment:manage")
  end

  pipeline :pools_manage do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "pools:manage")
  end

  pipeline :forwarding_manage do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "forwarding:manage")
  end

  pipeline :audit_view do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "audit:view")
  end

  pipeline :audit_export do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "audit:export")
  end

  pipeline :users_manage do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "users:manage")
  end

  pipeline :roles_view do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "roles:view")
  end

  pipeline :tokens_manage do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "tokens:manage")
  end

  pipeline :bundle_download do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "bundle:download")
  end

  pipeline :pcap_configure do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "pcap:configure")
  end

  pipeline :pcap_search do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "pcap:search")
  end

  pipeline :pcap_download do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "pcap:download")
  end

  pipeline :rules_deploy do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "rules:deploy")
  end

  pipeline :rules_manage do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "rules:manage")
  end

  pipeline :deployments_manage do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "deployments:manage")
  end

  # mTLS-authenticated internal API (Sensor_Agent → Config_Manager)
  pipeline :mtls_api do
    plug(:accepts, ["json"])
    plug(ConfigManagerWeb.Plugs.ApiVersionHeader)
    plug(ConfigManagerWeb.Plugs.MTLSAuth)
  end

  scope "/", ConfigManagerWeb do
    pipe_through(:browser)

    get("/api/docs", ApiDocsController, :index)
  end

  scope "/", ConfigManagerWeb do
    pipe_through(:browser)

    get("/login", SessionController, :new)
    post("/login", SessionController, :create)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth])

    get("/password/change", PasswordController, :edit)
    post("/password/change", PasswordController, :update)
    post("/logout", SessionController, :delete)
    delete("/logout", SessionController, :delete)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :dashboard_view])

    live_session :dashboard,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/", DashboardLive, :index)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :enrollment_manage])

    live_session :enrollment,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/enrollment", EnrollmentLive, :index)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :pools_manage])

    live_session :pool_management,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/pools/new", PoolLive.FormLive, :new)
      live("/pools/:id/edit", PoolLive.FormLive, :edit)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :sensors_view])

    live_session :sensor_pages,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/pools", PoolLive.IndexLive, :index)
      live("/pools/:id", PoolLive.ShowLive, :show)
      live("/pools/:id/sensors", PoolLive.SensorsLive, :index)
      live("/pools/:id/config", PoolLive.ConfigLive, :edit)
      live("/pools/:id/forwarding", ForwardingLive.OverviewLive, :index)
      live("/pools/:id/bpf", BpfLive.EditorLive, :index)
      live("/pools/:id/deployments", PoolLive.DeploymentsLive, :index)
      live("/pools/:id/drift", PoolLive.DriftLive, :index)
      live("/deployments", DeploymentLive.ListLive, :index)
      live("/deployments/:id", DeploymentLive.DetailLive, :show)
      live("/pcap-config", PcapConfigLive, :index)
      live("/rules", RuleDeploymentLive, :index)

      live("/rules/store", RulesLive.StoreLive, :index,
        private: %{required_permission: "sensors:view"}
      )

      live("/rules/categories", RulesLive.CategoriesLive, :index,
        private: %{required_permission: "sensors:view"}
      )

      live("/rules/repositories", RulesLive.RepositoriesLive, :index,
        private: %{required_permission: "sensors:view"}
      )

      live("/rules/rulesets", RulesLive.RulesetsLive, :index,
        private: %{required_permission: "sensors:view"}
      )

      live("/rules/rulesets/new", RulesLive.RulesetDetailLive, :new,
        private: %{required_permission: "sensors:view"}
      )

      live("/rules/rulesets/:id", RulesLive.RulesetDetailLive, :show,
        private: %{required_permission: "sensors:view"}
      )

      live("/rules/rulesets/:id/edit", RulesLive.RulesetDetailLive, :edit,
        private: %{required_permission: "sensors:view"}
      )

      live("/rules/deployments", RulesLive.DeploymentsLive, :index,
        private: %{required_permission: "sensors:view"}
      )

      live("/support-bundle", SupportBundleLive, :index)
      live("/sensors/:id", SensorDetailLive, :show)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :pcap_search])

    live_session :pcap,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/pcap", PcapLive.SearchLive, :index)
      live("/pcap/search", PcapLive.SearchLive, :search)
      live("/pcap/requests", PcapLive.RequestsLive, :index)
      live("/pcap/requests/:id", PcapLive.RequestDetailLive, :show)
      live("/pcap/requests/:id/manifest", PcapLive.ManifestLive, :show)
    end

    get("/pcap/requests/:id/manifest/export", PcapDownloadController, :export_manifest)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :pcap_download])

    get("/pcap/requests/:id/download", PcapDownloadController, :download)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :forwarding_manage])

    live_session :forwarding_management,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/pools/:id/forwarding/sinks/new", ForwardingLive.SinkFormLive, :new)
      live("/pools/:id/forwarding/sinks/:sink_id/edit", ForwardingLive.SinkFormLive, :edit)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :bundle_download])

    get("/support-bundle/download/:pod_id", SupportBundleController, :download)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :audit_view])

    live_session :audit,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/audit", AuditLive, :index)
    end
  end

  scope "/audit", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :audit_export])

    live_session :audit_export,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/export", AuditLive.ExportLive, :index)
    end

    get("/export/download", AuditExportController, :download)
  end

  scope "/admin", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :users_manage])

    live_session :admin_users,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/users", AdminLive.UsersLive, :index)
    end
  end

  scope "/admin", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :roles_view])

    live_session :admin_roles,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/roles", AdminLive.RolesLive, :index)
    end
  end

  scope "/admin", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :require_password_change, :tokens_manage])

    live_session :admin_tokens,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/api-tokens", AdminLive.ApiTokensLive, :index)
    end
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through(:api_docs_json)

    get("/openapi.json", Api.OpenApiController, :show)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :enrollment_manage])

    post("/enrollments/:id/approve", Api.EnrollmentController, :approve)
    post("/enrollments/:id/deny", Api.EnrollmentController, :deny)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :pcap_configure])

    post("/pcap-config", Api.PcapController, :update_config)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :pcap_search])

    get("/pcap/requests", Api.PcapController, :list_requests)
    get("/pcap/requests/:id", Api.PcapController, :show_request)
    get("/pcap/requests/:id/manifest", Api.PcapController, :manifest)
    post("/pcap/carve", Api.PcapController, :carve)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :pcap_download])

    get("/pcap/requests/:id/download", Api.PcapController, :download)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :rules_deploy])

    post("/rules/deploy", Api.RulesController, :deploy)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :sensors_view])

    get("/rules", Api.RulesController, :index)
    get("/rulesets", Api.RulesetsController, :index)
    get("/repositories", Api.RepositoriesController, :index)
    get("/deployments", Api.DeploymentsController, :index)
    get("/deployments/:id", Api.DeploymentsController, :show)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :rules_manage])

    post("/rules", Api.RulesController, :create)
    post("/rulesets", Api.RulesetsController, :create)
    post("/repositories", Api.RepositoriesController, :create)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :deployments_manage])

    post("/deployments", Api.DeploymentsController, :create)
    post("/deployments/:id/cancel", Api.DeploymentsController, :cancel)
    post("/deployments/:id/rollback", Api.DeploymentsController, :rollback)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :bundle_download])

    post("/support-bundles", Api.BundleController, :create)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :audit_view])

    get("/audit", Api.AuditController, :index)
  end

  scope "/api/v1", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :audit_export])

    get("/audit/export", Api.AuditController, :export)
  end

  scope "/api/v1/admin", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :users_manage])

    post("/users", Api.UsersController, :create)
  end

  scope "/api/v1/admin", ConfigManagerWeb do
    pipe_through([:api, :api_token_auth, :tokens_manage])

    post("/api-tokens", Api.TokensController, :create)
  end

  # Enrollment endpoints — called by Sensor_Agent during bootstrap
  scope "/api/v1", ConfigManagerWeb do
    pipe_through(:api)

    post("/enroll", EnrollmentController, :create)
    get("/enroll/status", EnrollmentController, :status)
    post("/certs/rotate", CertController, :rotate)
  end

  # mTLS-authenticated endpoints — Sensor_Agent control and health
  scope "/api/v1", ConfigManagerWeb do
    pipe_through(:mtls_api)

    get("/health/:pod_id", HealthController, :show)
    post("/enrollment/:id/approve", EnrollmentController, :approve)
    post("/enrollment/:id/deny", EnrollmentController, :deny)
    get("/crl", CRLController, :show)
  end

  scope "/api", ConfigManagerWeb do
    pipe_through(:api)

    match(:*, "/*path", Api.NotFoundController, :not_found)
  end
end
