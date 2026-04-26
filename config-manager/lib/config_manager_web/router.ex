defmodule ConfigManagerWeb.Router do
  use ConfigManagerWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {ConfigManagerWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # mTLS-authenticated internal API (Sensor_Agent → Config_Manager)
  pipeline :mtls_api do
    plug :accepts, ["json"]
    plug ConfigManagerWeb.Plugs.MTLSAuth
  end

  scope "/", ConfigManagerWeb do
    pipe_through :browser

    live "/", DashboardLive, :index
    live "/enrollment", EnrollmentLive, :index
    live "/pcap-config", PcapConfigLive, :index
    live "/rules", RuleDeploymentLive, :index
    live "/support-bundle", SupportBundleLive, :index
    get "/support-bundle/download/:pod_id", SupportBundleController, :download
  end

  # Enrollment endpoints — called by Sensor_Agent during bootstrap
  scope "/api/v1", ConfigManagerWeb do
    pipe_through :api

    post "/enroll", EnrollmentController, :create
    get "/enroll/status", EnrollmentController, :status
  end

  # mTLS-authenticated endpoints — Sensor_Agent control and health
  scope "/api/v1", ConfigManagerWeb do
    pipe_through :mtls_api

    get "/health/:pod_id", HealthController, :show
    post "/enrollment/:id/approve", EnrollmentController, :approve
    post "/enrollment/:id/deny", EnrollmentController, :deny
    get "/crl", CRLController, :show
  end
end
