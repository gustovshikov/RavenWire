defmodule Health.ConsumerStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:packets_received, 1, type: :uint64, json_name: "packetsReceived")
  field(:packets_dropped, 2, type: :uint64, json_name: "packetsDropped")
  field(:drop_percent, 3, type: :double, json_name: "dropPercent")
  field(:throughput_bps, 4, type: :double, json_name: "throughputBps")
  field(:bpf_restart_pending, 5, type: :bool, json_name: "bpfRestartPending")
  field(:drop_alert, 6, type: :bool, json_name: "dropAlert")
  field(:packets_written, 7, type: :uint64, json_name: "packetsWritten")
  field(:bytes_written, 8, type: :uint64, json_name: "bytesWritten")
  field(:wrap_count, 9, type: :uint64, json_name: "wrapCount")
  field(:socket_drops, 10, type: :uint64, json_name: "socketDrops")
  field(:socket_freeze_queue_drops, 11, type: :uint64, json_name: "socketFreezeQueueDrops")
  field(:overwrite_risk, 12, type: :bool, json_name: "overwriteRisk")
end

defmodule Health.CaptureStats.ConsumersEntry do
  @moduledoc false

  use Protobuf, map: true, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:key, 1, type: :string)
  field(:value, 2, type: Health.ConsumerStats)
end

defmodule Health.CaptureStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:consumers, 1,
    repeated: true,
    type: Health.CaptureStats.ConsumersEntry,
    map: true
  )
end

defmodule Health.ContainerHealth do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:name, 1, type: :string)
  field(:state, 2, type: :string)
  field(:uptime_seconds, 3, type: :int64, json_name: "uptimeSeconds")
  field(:cpu_percent, 4, type: :double, json_name: "cpuPercent")
  field(:memory_bytes, 5, type: :uint64, json_name: "memoryBytes")
end

defmodule Health.StorageStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:path, 1, type: :string)
  field(:total_bytes, 2, type: :uint64, json_name: "totalBytes")
  field(:used_bytes, 3, type: :uint64, json_name: "usedBytes")
  field(:available_bytes, 4, type: :uint64, json_name: "availableBytes")
  field(:used_percent, 5, type: :double, json_name: "usedPercent")
end

defmodule Health.ClockStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:offset_ms, 1, type: :int64, json_name: "offsetMs")
  field(:synchronized, 2, type: :bool)
  field(:source, 3, type: :string)
end

defmodule Health.SystemStats do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:uptime_seconds, 1, type: :int64, json_name: "uptimeSeconds")
  field(:cpu_percent, 2, type: :double, json_name: "cpuPercent")
  field(:cpu_count, 3, type: :int32, json_name: "cpuCount")
  field(:memory_total_bytes, 4, type: :uint64, json_name: "memoryTotalBytes")
  field(:memory_used_bytes, 5, type: :uint64, json_name: "memoryUsedBytes")
  field(:memory_available_bytes, 6, type: :uint64, json_name: "memoryAvailableBytes")
  field(:memory_used_percent, 7, type: :double, json_name: "memoryUsedPercent")
  field(:disk_path, 8, type: :string, json_name: "diskPath")
  field(:disk_total_bytes, 9, type: :uint64, json_name: "diskTotalBytes")
  field(:disk_used_bytes, 10, type: :uint64, json_name: "diskUsedBytes")
  field(:disk_available_bytes, 11, type: :uint64, json_name: "diskAvailableBytes")
  field(:disk_used_percent, 12, type: :double, json_name: "diskUsedPercent")
  field(:load1, 13, type: :double)
  field(:load5, 14, type: :double)
  field(:load15, 15, type: :double)
  field(:health, 16, type: :string)
end

defmodule Health.HealthReport do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:sensor_pod_id, 1, type: :string, json_name: "sensorPodId")
  field(:timestamp_unix_ms, 2, type: :int64, json_name: "timestampUnixMs")
  field(:containers, 3, repeated: true, type: Health.ContainerHealth)
  field(:capture, 4, type: Health.CaptureStats)
  field(:storage, 5, type: Health.StorageStats)
  field(:clock, 6, type: Health.ClockStats)
  field(:system, 7, type: Health.SystemStats)
end

defmodule Health.HealthAck do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  field(:sensor_pod_id, 1, type: :string, json_name: "sensorPodId")
  field(:ack_timestamp_unix_ms, 2, type: :int64, json_name: "ackTimestampUnixMs")
end
