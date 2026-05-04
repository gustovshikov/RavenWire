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
  end

  pipeline :require_auth do
    plug(ConfigManagerWeb.Plugs.RequireAuth)
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

  pipeline :audit_view do
    plug(ConfigManagerWeb.Plugs.RequirePermission, "audit:view")
  end

  # mTLS-authenticated internal API (Sensor_Agent → Config_Manager)
  pipeline :mtls_api do
    plug(:accepts, ["json"])
    plug(ConfigManagerWeb.Plugs.MTLSAuth)
  end

  scope "/", ConfigManagerWeb do
    pipe_through(:browser)

    get("/login", SessionController, :new)
    post("/login", SessionController, :create)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth])

    post("/logout", SessionController, :delete)
    delete("/logout", SessionController, :delete)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :dashboard_view])

    live_session :dashboard,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/", DashboardLive, :index)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :enrollment_manage])

    live_session :enrollment,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/enrollment", EnrollmentLive, :index)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :pools_manage])

    live_session :pool_management,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/pools/new", PoolLive.FormLive, :new)
      live("/pools/:id/edit", PoolLive.FormLive, :edit)
    end
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :sensors_view])

    live_session :sensor_pages,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/pools", PoolLive.IndexLive, :index)
      live("/pools/:id", PoolLive.ShowLive, :show)
      live("/pools/:id/sensors", PoolLive.SensorsLive, :index)
      live("/pools/:id/config", PoolLive.ConfigLive, :edit)
      live("/pools/:id/deployments", PoolLive.DeploymentsLive, :index)
      live("/pcap-config", PcapConfigLive, :index)
      live("/rules", RuleDeploymentLive, :index)
      live("/support-bundle", SupportBundleLive, :index)
      live("/sensors/:id", SensorDetailLive, :show)
    end

    get("/support-bundle/download/:pod_id", SupportBundleController, :download)
  end

  scope "/", ConfigManagerWeb do
    pipe_through([:browser, :require_auth, :audit_view])

    live_session :audit,
      on_mount: [{ConfigManagerWeb.AuthHelpers, :require_auth}] do
      live("/audit", AuditLive, :index)
    end
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
end
