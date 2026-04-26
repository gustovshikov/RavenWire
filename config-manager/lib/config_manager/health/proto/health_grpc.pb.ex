defmodule Health.HealthService.Service do
  @moduledoc false

  use GRPC.Service, name: "health.HealthService", protoc_gen_elixir_version: "0.12.0"

  rpc :StreamHealth,
      stream(Health.HealthReport),
      stream(Health.HealthAck)
end

defmodule Health.HealthService.Stub do
  @moduledoc false

  use GRPC.Stub, service: Health.HealthService.Service
end
