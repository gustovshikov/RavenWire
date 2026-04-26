defmodule ConfigManager.Health.GrpcEndpoint do
  @moduledoc """
  GRPC.Endpoint that wires the health stream server.
  Required by GRPC.Server.Supervisor in grpc >= 0.9.
  """
  use GRPC.Endpoint

  intercept GRPC.Server.Interceptors.Logger
  run ConfigManager.Health.GrpcServer
end
