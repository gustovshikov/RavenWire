defmodule Health.ConsumerStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :packets_received, 1, type: :uint64, json_name: "packetsReceived"
  field :packets_dropped, 2, type: :uint64, json_name: "packetsDropped"
  field :drop_percent, 3, type: :double, json_name: "dropPercent"
  field :throughput_bps, 4, type: :double, json_name: "throughputBps"
  field :bpf_restart_pending, 5, type: :bool, json_name: "bpfRestartPending"
end

defmodule Health.CaptureStats.ConsumersEntry do
  @moduledoc false

  use Protobuf, map: true, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :key, 1, type: :string
  field :value, 2, type: Health.ConsumerStats
end

defmodule Health.CaptureStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :consumers, 1,
    repeated: true,
    type: Health.CaptureStats.ConsumersEntry,
    map: true
end

defmodule Health.ContainerHealth do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :name, 1, type: :string
  field :state, 2, type: :string
  field :uptime_seconds, 3, type: :int64, json_name: "uptimeSeconds"
  field :cpu_percent, 4, type: :double, json_name: "cpuPercent"
  field :memory_bytes, 5, type: :uint64, json_name: "memoryBytes"
end

defmodule Health.StorageStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :path, 1, type: :string
  field :total_bytes, 2, type: :uint64, json_name: "totalBytes"
  field :used_bytes, 3, type: :uint64, json_name: "usedBytes"
  field :available_bytes, 4, type: :uint64, json_name: "availableBytes"
  field :used_percent, 5, type: :double, json_name: "usedPercent"
end

defmodule Health.ClockStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :offset_ms, 1, type: :int64, json_name: "offsetMs"
  field :synchronized, 2, type: :bool
  field :source, 3, type: :string
end

defmodule Health.HealthReport do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :sensor_pod_id, 1, type: :string, json_name: "sensorPodId"
  field :timestamp_unix_ms, 2, type: :int64, json_name: "timestampUnixMs"
  field :containers, 3, repeated: true, type: Health.ContainerHealth
  field :capture, 4, type: Health.CaptureStats
  field :storage, 5, type: Health.StorageStats
  field :clock, 6, type: Health.ClockStats
end

defmodule Health.HealthAck do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field :sensor_pod_id, 1, type: :string, json_name: "sensorPodId"
  field :ack_timestamp_unix_ms, 2, type: :int64, json_name: "ackTimestampUnixMs"
end
