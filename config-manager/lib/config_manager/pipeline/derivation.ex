defmodule ConfigManager.Pipeline.Derivation do
  @moduledoc """
  Pure derivation helpers for live sensor pipeline visualization.

  This module transforms the latest HealthReport plus sensor/config metadata into
  deterministic maps for rendering. It does not read ETS, query the database,
  subscribe to PubSub, or call wall-clock time.
  """

  @type segment_state :: :healthy | :degraded | :failed | :disabled | :pending_reload | :no_data
  @type connector_flow_state :: :flowing | :degraded | :idle | :stopped | :unknown
  @type speed_tier :: :gbps | :mbps | :kbps | :zero | :unknown

  @type segment :: %{
          id: String.t(),
          label: String.t(),
          state: segment_state(),
          metrics: map(),
          warnings: [String.t()],
          badges: [map()],
          tooltip: map(),
          accessible_summary: String.t()
        }

  @type connector :: %{
          id: String.t(),
          source_id: String.t(),
          target_id: String.t(),
          throughput_bps: number() | nil,
          throughput_label: String.t(),
          secondary_label: String.t() | nil,
          flow_state: connector_flow_state(),
          speed_tier: speed_tier(),
          capture_mode_context: atom() | String.t() | nil,
          accessible_summary: String.t()
        }

  @type pipeline_state :: %{
          segments: [segment()],
          connectors: [connector()],
          topology: :canonical,
          stale: boolean(),
          stale_age_seconds: non_neg_integer() | nil,
          last_report_timestamp: DateTime.t() | nil,
          sensor_status: String.t() | nil,
          status_banners: [map()],
          summary_rows: [map()],
          reporting: boolean()
        }

  @type aggregate_segment :: %{
          id: String.t(),
          label: String.t(),
          overall_state: segment_state(),
          state_counts: %{segment_state() => non_neg_integer()},
          badges: [map()],
          accessible_summary: String.t()
        }

  @type aggregate_pipeline_state :: %{
          segments: [aggregate_segment()],
          connectors: [connector()],
          topology: :canonical,
          total_members: non_neg_integer(),
          reporting_members: non_neg_integer(),
          summary_rows: [map()]
        }

  @drop_percent_threshold 5.0
  @cpu_percent_threshold 90.0
  @storage_warning_threshold 85.0
  @storage_critical_threshold 95.0
  @dash "—"

  @canonical_segment_ids [
    "mirror_port",
    "af_packet",
    "zeek",
    "suricata",
    "pcap_ring",
    "vector",
    "forwarding_sinks"
  ]

  @segment_labels %{
    "mirror_port" => "Mirror Port",
    "af_packet" => "AF_PACKET",
    "zeek" => "Zeek",
    "suricata" => "Suricata",
    "pcap_ring" => "PCAP Ring",
    "vector" => "Vector",
    "forwarding_sinks" => "Forwarding Sinks"
  }

  @expected_containers %{
    "zeek" => ["zeek", "systemd-zeek"],
    "suricata" => ["suricata", "systemd-suricata"],
    "pcap_ring" => ["pcap_ring_writer", "pcap-ring-writer", "systemd-pcap-ring-writer"],
    "vector" => ["vector", "systemd-vector"]
  }

  @canonical_capture_consumers %{
    "zeek" => "zeek",
    "suricata" => "suricata",
    "pcap_ring_writer" => "pcap_ring",
    "pcap-ring-writer" => "pcap_ring",
    "systemd-pcap-ring-writer" => "pcap_ring"
  }

  @segment_states [:healthy, :degraded, :failed, :disabled, :pending_reload, :no_data]

  @doc """
  Derives the complete pipeline state for a single sensor.
  """
  @spec derive_sensor_pipeline(map() | nil, map(), keyword()) :: pipeline_state()
  def derive_sensor_pipeline(health_report, sensor_pod, opts) do
    capture_stats = field(health_report, :capture)
    capture_consumers = capture_consumers(capture_stats)
    capture_mode = Keyword.get(opts, :capture_mode)
    forwarding_config = forwarding_config(opts)

    {stale?, stale_age_seconds} =
      check_staleness(field(health_report, :timestamp_unix_ms), opts)

    mirror_port = derive_mirror_port(health_report)
    af_packet = derive_af_packet(capture_stats)

    zeek =
      derive_analysis_tool(
        "zeek",
        container_for(health_report, "zeek"),
        consumer_for(capture_consumers, "zeek"),
        opts
      )

    suricata =
      derive_analysis_tool(
        "suricata",
        container_for(health_report, "suricata"),
        consumer_for(capture_consumers, "suricata"),
        opts
      )

    pcap_ring =
      "pcap_ring"
      |> derive_analysis_tool(
        container_for(health_report, "pcap_ring"),
        consumer_for(capture_consumers, "pcap_ring"),
        opts
      )
      |> add_storage_badge(field(health_report, :storage))

    dynamic_segments = derive_dynamic_capture_consumers(capture_consumers)
    vector = derive_vector(container_for(health_report, "vector"), nil)
    forwarding_sinks = derive_forwarding_sinks(forwarding_config, nil)

    segments =
      [
        mirror_port,
        af_packet,
        zeek,
        suricata,
        pcap_ring
      ] ++ dynamic_segments ++ [vector, forwarding_sinks]

    connectors =
      derive_connectors(segments, capture_consumers,
        stale: stale?,
        capture_mode: capture_mode
      )

    status_banners =
      status_banners(health_report, sensor_pod, stale?, stale_age_seconds, opts)

    %{
      segments: segments,
      connectors: connectors,
      topology: :canonical,
      stale: stale?,
      stale_age_seconds: stale_age_seconds,
      last_report_timestamp: report_datetime(field(health_report, :timestamp_unix_ms)),
      sensor_status: string_field(sensor_pod, :status),
      status_banners: status_banners,
      summary_rows: Enum.map(segments, &summary_row/1),
      reporting: not is_nil(health_report)
    }
  end

  @doc """
  Aggregates per-sensor pipeline states into a pool-level state map.
  """
  @spec aggregate_pool_pipeline([{String.t(), String.t(), pipeline_state()}]) ::
          aggregate_pipeline_state()
  def aggregate_pool_pipeline(member_states) do
    segments =
      Enum.map(@canonical_segment_ids, fn segment_id ->
        label = Map.fetch!(@segment_labels, segment_id)

        states =
          Enum.map(member_states, fn {_sensor_id, _sensor_name, pipeline_state} ->
            pipeline_state
            |> segment_by_id(segment_id)
            |> case do
              nil -> :no_data
              segment -> Map.get(segment, :state, :no_data)
            end
          end)

        state_counts = state_counts(states)
        overall_state = worst_state(states)

        %{
          id: segment_id,
          label: label,
          overall_state: overall_state,
          state_counts: state_counts,
          badges: aggregate_badges(state_counts),
          accessible_summary: aggregate_summary(label, overall_state, state_counts)
        }
      end)

    connectors = aggregate_connectors(segments)

    %{
      segments: segments,
      connectors: connectors,
      topology: :canonical,
      total_members: length(member_states),
      reporting_members:
        Enum.count(member_states, fn {_sensor_id, _sensor_name, pipeline_state} ->
          Map.get(pipeline_state, :reporting, false)
        end),
      summary_rows: Enum.map(segments, &aggregate_summary_row/1)
    }
  end

  @doc """
  Derives a connector state from source/target segment state and structured telemetry.
  """
  @spec derive_connector(
          segment() | aggregate_segment(),
          segment() | aggregate_segment(),
          keyword()
        ) ::
          connector()
  def derive_connector(source, target, opts \\ []) do
    source_id = Map.fetch!(source, :id)
    target_id = Map.fetch!(target, :id)
    source_label = Map.get(source, :label, source_id)
    target_label = Map.get(target, :label, target_id)
    throughput_bps = Keyword.get(opts, :throughput_bps)
    stale? = Keyword.get(opts, :stale, false)
    capture_mode = Keyword.get(opts, :capture_mode)

    flow_state =
      connector_flow_state(segment_state(source), segment_state(target), throughput_bps,
        stale: stale?,
        capture_mode: capture_mode,
        source_id: source_id,
        target_id: target_id,
        pcap_flush_active?: Keyword.get(opts, :pcap_flush_active?, false)
      )

    throughput_label = format_throughput(throughput_bps)
    secondary_label = Keyword.get(opts, :secondary_label)

    %{
      id: "#{source_id}->#{target_id}",
      source_id: source_id,
      target_id: target_id,
      throughput_bps: throughput_bps,
      throughput_label: throughput_label,
      secondary_label: secondary_label,
      flow_state: flow_state,
      speed_tier: classify_speed_tier(throughput_bps),
      capture_mode_context: capture_mode,
      accessible_summary:
        connector_summary(
          source_label,
          target_label,
          throughput_label,
          secondary_label,
          flow_state
        )
    }
  end

  @doc """
  Derives Mirror Port from limited system telemetry.
  """
  @spec derive_mirror_port(map() | nil) :: segment()
  def derive_mirror_port(health_report) do
    system = field(health_report, :system)
    interface = system |> field(:capture_interface) |> present_string()
    driver = system |> field(:nic_driver) |> present_string()
    af_packet_available = field(system, :af_packet_available)

    state =
      cond do
        is_nil(system) or is_nil(interface) -> :no_data
        af_packet_available == true -> :healthy
        af_packet_available == false -> :degraded
        true -> :no_data
      end

    metrics = %{
      capture_interface: interface,
      nic_driver: driver,
      af_packet_available: af_packet_available
    }

    warnings =
      if is_nil(interface) do
        ["Capture interface telemetry is not available."]
      else
        ["Physical mirror/SPAN source health is not reported by current telemetry."]
      end

    base_segment("mirror_port", state,
      metrics: metrics,
      warnings: warnings,
      tooltip: %{
        capture_interface: display(interface),
        nic_driver: display(driver),
        af_packet_available: availability_label(af_packet_available),
        telemetry_scope:
          "Local capture interface only; physical mirror/SPAN source health is not reported."
      }
    )
  end

  @doc """
  Derives AF_PACKET state from capture consumer stats.
  """
  @spec derive_af_packet(map() | nil) :: segment()
  def derive_af_packet(capture_stats) do
    consumers = capture_consumers(capture_stats)

    state =
      cond do
        consumers == [] ->
          :no_data

        Enum.any?(consumers, fn {_name, stats} ->
          drop_percent(stats) > @drop_percent_threshold
        end) ->
          :degraded

        Enum.any?(consumers, fn {_name, stats} -> field(stats, :bpf_restart_pending) == true end) ->
          :pending_reload

        true ->
          :healthy
      end

    aggregate_throughput_bps = aggregate_throughput(consumers)

    base_segment("af_packet", state,
      metrics: %{
        consumer_count: length(consumers),
        aggregate_throughput_bps: aggregate_throughput_bps,
        aggregate_throughput: format_throughput(aggregate_throughput_bps),
        max_drop_percent: max_drop_percent(consumers)
      },
      warnings: af_packet_warnings(consumers),
      tooltip: %{
        aggregate_throughput: format_throughput(aggregate_throughput_bps),
        consumers: Enum.map(consumers, fn {name, stats} -> consumer_tooltip(name, stats) end),
        bpf_restart_pending:
          Enum.any?(consumers, fn {_name, stats} -> field(stats, :bpf_restart_pending) == true end)
      }
    )
  end

  @doc """
  Derives a Zeek, Suricata, or PCAP Ring segment from container and consumer stats.
  """
  @spec derive_analysis_tool(String.t(), map() | nil, map() | nil, keyword()) :: segment()
  def derive_analysis_tool(segment_id, container, consumer_stats, opts \\ []) do
    disabled? = disabled_segment?(segment_id, opts)

    state =
      cond do
        disabled? ->
          :disabled

        is_nil(container) ->
          :no_data

        container_state(container) in ["error", "stopped"] ->
          :failed

        container_state(container) == "restarting" ->
          :degraded

        container_state(container) == "running" and analysis_degraded?(container, consumer_stats) ->
          :degraded

        container_state(container) == "running" ->
          :healthy

        true ->
          :degraded
      end

    label = Map.get(@segment_labels, segment_id, segment_id)

    base_segment(segment_id, state,
      metrics: container_metrics(container, consumer_stats),
      warnings:
        analysis_warnings(label, state, container, consumer_stats) ++
          pcap_capture_mode_warnings(segment_id, opts),
      tooltip:
        %{
          container_state: display(container_state(container)),
          uptime_seconds: field(container, :uptime_seconds),
          cpu_percent: field(container, :cpu_percent),
          memory_bytes: field(container, :memory_bytes),
          packets_received: field(consumer_stats, :packets_received),
          packets_dropped: field(consumer_stats, :packets_dropped),
          drop_percent: field(consumer_stats, :drop_percent)
        }
        |> maybe_add_pcap_metrics(segment_id, consumer_stats)
    )
  end

  @doc """
  Derives Vector state from container health and optional future forwarding data.
  """
  @spec derive_vector(map() | nil, map() | nil) :: segment()
  def derive_vector(container, forwarding_data) do
    state =
      cond do
        is_nil(container) ->
          :no_data

        container_state(container) in ["error", "stopped"] ->
          :failed

        container_state(container) == "restarting" ->
          :degraded

        container_state(container) == "running" and forwarding_buffer_degraded?(forwarding_data) ->
          :degraded

        container_state(container) == "running" ->
          :healthy

        true ->
          :degraded
      end

    base_segment("vector", state,
      metrics: container_metrics(container, nil),
      warnings: analysis_warnings("Vector", state, container, nil),
      tooltip: %{
        container_state: display(container_state(container)),
        uptime_seconds: field(container, :uptime_seconds),
        cpu_percent: field(container, :cpu_percent),
        memory_bytes: field(container, :memory_bytes),
        forwarding_buffer_used_percent: field(forwarding_data, :buffer_used_percent),
        forwarding_telemetry:
          "Vector sink runtime telemetry is not available in the current HealthReport."
      }
    )
  end

  @doc """
  Derives the single aggregate Forwarding Sinks segment.
  """
  @spec derive_forwarding_sinks(map() | nil, map() | nil) :: segment()
  def derive_forwarding_sinks(forwarding_config, forwarding_data) do
    sinks = Map.get(forwarding_config || %{}, :sinks, [])
    summary = Map.get(forwarding_config || %{}, :summary, %{})
    sink_count = Map.get(summary, :sink_count, length(sinks)) || length(sinks)

    enabled_count =
      Map.get(summary, :enabled_count, Enum.count(sinks, &truthy?(field(&1, :enabled)))) || 0

    disabled_count = max(sink_count - enabled_count, 0)

    state =
      cond do
        runtime_forwarding_state(forwarding_data) in [:healthy, :degraded, :failed] ->
          runtime_forwarding_state(forwarding_data)

        sink_count > 0 and enabled_count == 0 ->
          :disabled

        true ->
          :no_data
      end

    sink_rows = Enum.map(sinks, &sink_tooltip/1)

    badges =
      [
        if(sink_count > 0,
          do: %{kind: :sink_count, label: "#{enabled_count}/#{sink_count} enabled"}
        ),
        if(disabled_count > 0, do: %{kind: :disabled_count, label: "#{disabled_count} disabled"}),
        if(state == :no_data, do: %{kind: :no_data, label: "runtime no data"})
      ]
      |> Enum.reject(&is_nil/1)

    base_segment("forwarding_sinks", state,
      metrics: %{
        sink_count: sink_count,
        enabled_count: enabled_count,
        disabled_count: disabled_count,
        schema_mode: Map.get(summary, :schema_mode),
        sinks:
          Enum.map(sink_rows, &Map.take(&1, [:name, :sink_type, :enabled, :destination_label]))
      },
      badges: badges,
      warnings: forwarding_warnings(state, sink_count, enabled_count),
      tooltip: %{
        schema_mode: display(Map.get(summary, :schema_mode)),
        sink_count: sink_count,
        enabled_count: enabled_count,
        disabled_count: disabled_count,
        sinks: sink_rows,
        runtime_telemetry:
          "Forwarding sink delivery telemetry is not available in the current HealthReport."
      }
    )
  end

  @doc """
  Classifies PCAP ring storage usage.
  """
  @spec derive_storage_warnings(map() | nil) :: %{
          level: :none | :warning | :critical | :no_data,
          label: String.t(),
          used_percent: float() | nil
        }
  def derive_storage_warnings(storage_stats) do
    used_percent = numeric(field(storage_stats, :used_percent))

    cond do
      is_nil(storage_stats) or is_nil(used_percent) ->
        %{level: :no_data, label: "Storage data not available", used_percent: nil}

      used_percent > @storage_critical_threshold ->
        %{level: :critical, label: "Storage critical", used_percent: used_percent}

      used_percent > @storage_warning_threshold ->
        %{level: :warning, label: "Storage warning", used_percent: used_percent}

      true ->
        %{level: :none, label: "Storage normal", used_percent: used_percent}
    end
  end

  @doc """
  Formats throughput while preserving the distinction between nil and zero.
  """
  @spec format_throughput(number() | nil) :: String.t()
  def format_throughput(nil), do: @dash
  def format_throughput(bps) when not is_number(bps), do: @dash
  def format_throughput(bps) when bps < 0, do: @dash

  def format_throughput(bps) do
    cond do
      bps >= 1_000_000_000 -> decimal(bps / 1_000_000_000) <> " Gbps"
      bps >= 1_000_000 -> decimal(bps / 1_000_000) <> " Mbps"
      bps >= 1_000 -> decimal(bps / 1_000) <> " Kbps"
      true -> "#{round(bps)} bps"
    end
  end

  @doc """
  Formats a packet count with an optional rate annotation.
  """
  @spec format_packet_count(integer() | nil, number() | nil) :: String.t()
  def format_packet_count(count, rate \\ nil)
  def format_packet_count(nil, _rate), do: @dash
  def format_packet_count(count, _rate) when not is_integer(count), do: @dash
  def format_packet_count(count, _rate) when count < 0, do: @dash
  def format_packet_count(count, nil), do: comma_integer(count)
  def format_packet_count(count, rate) when not is_number(rate), do: comma_integer(count)
  def format_packet_count(count, rate), do: "#{comma_integer(count)} (#{format_rate(rate)} pps)"

  @doc """
  Classifies throughput for connector animation speed.
  """
  @spec classify_speed_tier(number() | nil) :: speed_tier()
  def classify_speed_tier(nil), do: :unknown
  def classify_speed_tier(bps) when not is_number(bps) or bps < 0, do: :unknown
  def classify_speed_tier(0), do: :zero
  def classify_speed_tier(bps) when bps < 1_000_000, do: :kbps
  def classify_speed_tier(bps) when bps < 1_000_000_000, do: :mbps
  def classify_speed_tier(_bps), do: :gbps

  @doc """
  Returns `{stale?, age_seconds}` for a HealthReport timestamp.
  """
  @spec check_staleness(integer() | nil, keyword()) :: {boolean(), non_neg_integer() | nil}
  def check_staleness(timestamp_unix_ms, opts) do
    threshold = Keyword.get(opts, :stale_threshold_sec, 60)
    now = Keyword.fetch!(opts, :now)

    with true <- is_integer(timestamp_unix_ms) and timestamp_unix_ms > 0,
         {:ok, report_time} <- DateTime.from_unix(timestamp_unix_ms, :millisecond) do
      age = max(DateTime.diff(now, report_time, :second), 0)
      {age > threshold, age}
    else
      _ -> {true, nil}
    end
  end

  @doc """
  Computes the worst reporting state. `:no_data` does not override reporting members.
  """
  @spec worst_state([segment_state()]) :: segment_state()
  def worst_state(states) do
    reporting_states = Enum.reject(states, &(&1 == :no_data))

    cond do
      states == [] -> :no_data
      reporting_states == [] -> :no_data
      :failed in reporting_states -> :failed
      :degraded in reporting_states -> :degraded
      :pending_reload in reporting_states -> :pending_reload
      :healthy in reporting_states -> :healthy
      :disabled in reporting_states -> :disabled
      true -> :no_data
    end
  end

  def canonical_segment_ids, do: @canonical_segment_ids

  defp derive_dynamic_capture_consumers(consumers) do
    consumers
    |> Enum.reject(fn {name, _stats} -> canonical_capture_consumer?(name) end)
    |> Enum.sort_by(fn {name, _stats} -> normalize_name(name) end)
    |> Enum.map(fn {name, stats} ->
      id = "capture_consumer:#{sanitize_id(name)}"

      state =
        cond do
          is_nil(stats) -> :no_data
          drop_percent(stats) > @drop_percent_threshold -> :degraded
          field(stats, :bpf_restart_pending) == true -> :pending_reload
          true -> :healthy
        end

      base_segment(id, state,
        label: to_string(name),
        metrics: consumer_metrics(stats),
        warnings: consumer_warnings(stats),
        tooltip: consumer_tooltip(name, stats)
      )
    end)
  end

  defp derive_connectors(segments, consumers, opts) do
    segment_map = Map.new(segments, &{&1.id, &1})
    stale? = Keyword.get(opts, :stale, false)
    capture_mode = Keyword.get(opts, :capture_mode)

    analysis_segment_ids =
      ["zeek", "suricata", "pcap_ring"] ++
        (segments
         |> Enum.map(& &1.id)
         |> Enum.filter(&String.starts_with?(&1, "capture_consumer:")))

    mirror_to_af =
      derive_connector(segment_map["mirror_port"], segment_map["af_packet"],
        throughput_bps: aggregate_throughput(consumers),
        stale: stale?,
        capture_mode: capture_mode
      )

    af_to_analysis =
      Enum.map(analysis_segment_ids, fn segment_id ->
        original_consumer_name = consumer_name_for_segment_id(segment_id, consumers)
        consumer_stats = consumer_for(consumers, segment_id)

        derive_connector(segment_map["af_packet"], segment_map[segment_id],
          throughput_bps: numeric(field(consumer_stats, :throughput_bps)),
          secondary_label: format_packet_count(field(consumer_stats, :packets_received)),
          stale: stale?,
          capture_mode: capture_mode
        )
        |> maybe_unknown_secondary_label(original_consumer_name)
      end)

    analysis_to_vector =
      Enum.map(analysis_segment_ids, fn segment_id ->
        derive_connector(segment_map[segment_id], segment_map["vector"],
          throughput_bps: nil,
          stale: stale?,
          capture_mode: capture_mode
        )
      end)

    vector_to_forwarding =
      derive_connector(segment_map["vector"], segment_map["forwarding_sinks"],
        throughput_bps: nil,
        stale: stale?,
        capture_mode: capture_mode
      )

    [mirror_to_af] ++ af_to_analysis ++ analysis_to_vector ++ [vector_to_forwarding]
  end

  defp aggregate_connectors(segments) do
    segment_map = Map.new(segments, &{&1.id, &1})

    [
      {"mirror_port", "af_packet"},
      {"af_packet", "zeek"},
      {"af_packet", "suricata"},
      {"af_packet", "pcap_ring"},
      {"zeek", "vector"},
      {"suricata", "vector"},
      {"pcap_ring", "vector"},
      {"vector", "forwarding_sinks"}
    ]
    |> Enum.map(fn {source_id, target_id} ->
      derive_connector(segment_map[source_id], segment_map[target_id], throughput_bps: nil)
    end)
  end

  defp connector_flow_state(source_state, target_state, throughput_bps, opts) do
    cond do
      source_state in [:failed, :disabled] or target_state in [:failed, :disabled] ->
        :stopped

      source_state == :no_data or target_state == :no_data ->
        :unknown

      source_state in [:degraded, :pending_reload] or target_state in [:degraded, :pending_reload] ->
        :degraded

      Keyword.get(opts, :stale, false) ->
        :degraded

      pcap_alert_driven_idle?(opts) ->
        :idle

      is_nil(throughput_bps) ->
        :unknown

      throughput_bps == 0 ->
        :idle

      is_number(throughput_bps) and throughput_bps > 0 ->
        :flowing

      true ->
        :unknown
    end
  end

  defp pcap_alert_driven_idle?(opts) do
    capture_mode = Keyword.get(opts, :capture_mode)
    source_id = Keyword.get(opts, :source_id)
    target_id = Keyword.get(opts, :target_id)

    capture_mode in [:alert_driven, "alert_driven"] and
      (source_id == "pcap_ring" or target_id == "pcap_ring") and
      Keyword.get(opts, :pcap_flush_active?, false) != true
  end

  defp base_segment(id, state, opts) do
    label = Keyword.get(opts, :label, Map.get(@segment_labels, id, id))
    metrics = Keyword.get(opts, :metrics, %{})
    warnings = Keyword.get(opts, :warnings, [])
    badges = Keyword.get(opts, :badges, [])
    tooltip = Keyword.get(opts, :tooltip, %{})

    %{
      id: id,
      label: label,
      state: state,
      metrics: metrics,
      warnings: warnings,
      badges: badges,
      tooltip: tooltip,
      accessible_summary:
        Keyword.get(
          opts,
          :accessible_summary,
          segment_summary(label, state, metrics, warnings, badges)
        )
    }
  end

  defp add_storage_badge(segment, storage_stats) do
    warning = derive_storage_warnings(storage_stats)

    storage_metrics = %{
      storage_used_percent: warning.used_percent,
      storage_used_label: storage_used_label(warning.used_percent),
      storage_total_bytes: field(storage_stats, :total_bytes),
      storage_total_label: format_bytes(field(storage_stats, :total_bytes)),
      storage_path: field(storage_stats, :path)
    }

    badge =
      case warning.level do
        :none -> nil
        level -> %{kind: :"storage_#{level}", label: warning.label}
      end

    segment
    |> update_in([:metrics], &Map.merge(&1, storage_metrics))
    |> update_in(
      [:tooltip],
      &Map.merge(&1, %{storage: storage_metrics, storage_level: warning.level})
    )
    |> update_in([:badges], fn badges -> if badge, do: badges ++ [badge], else: badges end)
    |> update_in([:warnings], fn warnings ->
      if warning.level in [:warning, :critical, :no_data],
        do: warnings ++ [warning.label],
        else: warnings
    end)
  end

  defp status_banners(nil, sensor_pod, _stale?, _age, _opts) do
    [
      %{
        kind: :no_health,
        label: "No Health Data",
        message: "This sensor is not currently reporting health data."
      }
    ]
    |> Kernel.++(sensor_status_banners(sensor_pod))
  end

  defp status_banners(_health_report, sensor_pod, stale?, stale_age_seconds, opts) do
    stale_banner =
      if stale? do
        %{
          kind: :stale,
          label: "Stale Health Data",
          message: stale_message(stale_age_seconds)
        }
      end

    degradation_banners =
      opts
      |> Keyword.get(:degradation_reasons, [])
      |> Enum.map(fn reason ->
        %{
          kind: :degraded,
          label: "Degraded",
          message: "Degradation reason: #{reason_label(reason)}"
        }
      end)

    [stale_banner]
    |> Enum.reject(&is_nil/1)
    |> Kernel.++(sensor_status_banners(sensor_pod))
    |> Kernel.++(degradation_banners)
  end

  defp sensor_status_banners(sensor_pod) do
    case string_field(sensor_pod, :status) do
      "pending" ->
        [
          %{
            kind: :pending,
            label: "Pending Enrollment",
            message: "This sensor is pending enrollment."
          }
        ]

      "revoked" ->
        [
          %{
            kind: :revoked,
            label: "Revoked Sensor",
            message: "This sensor identity has been revoked."
          }
        ]

      _ ->
        []
    end
  end

  defp forwarding_config(opts) do
    %{
      sinks: Keyword.get(opts, :forwarding_sinks, []),
      summary: Keyword.get(opts, :forwarding_summary, %{})
    }
  end

  defp container_for(nil, _segment_id), do: nil

  defp container_for(health_report, segment_id) do
    aliases = Map.fetch!(@expected_containers, segment_id)
    containers = field(health_report, :containers, []) || []

    Enum.find(containers, fn container ->
      field(container, :name) in aliases
    end)
  end

  defp capture_consumers(nil), do: []

  defp capture_consumers(capture_stats) do
    case field(capture_stats, :consumers) do
      consumers when is_map(consumers) ->
        consumers
        |> Enum.map(fn {name, stats} -> {to_string(name), stats} end)
        |> Enum.sort_by(fn {name, _stats} -> normalize_name(name) end)

      _ ->
        []
    end
  end

  defp consumer_for(consumers, segment_id) when is_list(consumers) do
    Enum.find_value(consumers, fn {name, stats} ->
      cond do
        segment_id == "zeek" and normalize_name(name) == "zeek" ->
          stats

        segment_id == "suricata" and normalize_name(name) == "suricata" ->
          stats

        segment_id == "pcap_ring" and canonical_capture_consumer?(name) and
            Map.get(@canonical_capture_consumers, normalize_name(name)) == "pcap_ring" ->
          stats

        String.starts_with?(segment_id, "capture_consumer:") and
            segment_id == "capture_consumer:#{sanitize_id(name)}" ->
          stats

        true ->
          nil
      end
    end)
  end

  defp consumer_for(_consumers, _segment_id), do: nil

  defp consumer_name_for_segment_id("zeek", _consumers), do: "zeek"
  defp consumer_name_for_segment_id("suricata", _consumers), do: "suricata"
  defp consumer_name_for_segment_id("pcap_ring", _consumers), do: "pcap_ring_writer"

  defp consumer_name_for_segment_id(segment_id, consumers) do
    Enum.find_value(consumers, fn {name, _stats} ->
      if segment_id == "capture_consumer:#{sanitize_id(name)}", do: name
    end)
  end

  defp canonical_capture_consumer?(name) do
    Map.has_key?(@canonical_capture_consumers, normalize_name(name))
  end

  defp analysis_degraded?(container, consumer_stats) do
    numeric(field(container, :cpu_percent), 0.0) > @cpu_percent_threshold or
      drop_percent(consumer_stats) > @drop_percent_threshold
  end

  defp forwarding_buffer_degraded?(nil), do: false

  defp forwarding_buffer_degraded?(forwarding_data) do
    numeric(field(forwarding_data, :buffer_used_percent), 0.0) > @storage_warning_threshold
  end

  defp runtime_forwarding_state(nil), do: nil
  defp runtime_forwarding_state(forwarding_data), do: field(forwarding_data, :state)

  defp disabled_segment?(segment_id, opts) do
    disabled_segments = Keyword.get(opts, :disabled_segments, [])
    segment_id in disabled_segments or String.to_atom(segment_id) in disabled_segments
  end

  defp container_metrics(container, consumer_stats) do
    %{
      container_state: container_state(container),
      uptime_seconds: field(container, :uptime_seconds),
      cpu_percent: field(container, :cpu_percent),
      memory_bytes: field(container, :memory_bytes),
      memory_label: format_bytes(field(container, :memory_bytes)),
      packets_received: field(consumer_stats, :packets_received),
      packets_dropped: field(consumer_stats, :packets_dropped),
      drop_percent: field(consumer_stats, :drop_percent),
      throughput_bps: numeric(field(consumer_stats, :throughput_bps)),
      throughput: format_throughput(field(consumer_stats, :throughput_bps))
    }
  end

  defp consumer_metrics(stats) do
    %{
      packets_received: field(stats, :packets_received),
      packets_dropped: field(stats, :packets_dropped),
      packets_received_label: format_packet_count(field(stats, :packets_received)),
      drop_percent: field(stats, :drop_percent),
      throughput_bps: numeric(field(stats, :throughput_bps)),
      throughput: format_throughput(field(stats, :throughput_bps)),
      bpf_restart_pending: field(stats, :bpf_restart_pending)
    }
  end

  defp af_packet_warnings([]), do: ["Capture data is not available."]

  defp af_packet_warnings(consumers) do
    []
    |> maybe_add_warning(
      Enum.any?(consumers, fn {_name, stats} -> drop_percent(stats) > @drop_percent_threshold end),
      "One or more capture consumers exceed the drop threshold."
    )
    |> maybe_add_warning(
      Enum.any?(consumers, fn {_name, stats} -> field(stats, :bpf_restart_pending) == true end),
      "BPF restart is pending."
    )
  end

  defp analysis_warnings(label, :no_data, _container, _consumer_stats),
    do: ["#{label} telemetry is not available."]

  defp analysis_warnings(label, :failed, container, _consumer_stats),
    do: ["#{label} container is #{display(container_state(container))}."]

  defp analysis_warnings(label, :degraded, container, consumer_stats) do
    []
    |> maybe_add_warning(
      container_state(container) == "restarting",
      "#{label} container is restarting."
    )
    |> maybe_add_warning(
      numeric(field(container, :cpu_percent), 0.0) > @cpu_percent_threshold,
      "#{label} CPU exceeds #{@cpu_percent_threshold}%."
    )
    |> maybe_add_warning(
      drop_percent(consumer_stats) > @drop_percent_threshold,
      "#{label} capture drops exceed #{@drop_percent_threshold}%."
    )
    |> case do
      [] -> ["#{label} is degraded."]
      warnings -> warnings
    end
  end

  defp analysis_warnings(_label, _state, _container, _consumer_stats), do: []

  defp pcap_capture_mode_warnings("pcap_ring", opts) do
    if Keyword.get(opts, :capture_mode) in [:alert_driven, "alert_driven"] do
      [
        "Alert Driven PCAP flush telemetry is not reported; PCAP flow stays idle until explicit flush data is available."
      ]
    else
      []
    end
  end

  defp pcap_capture_mode_warnings(_segment_id, _opts), do: []

  defp consumer_warnings(stats) do
    []
    |> maybe_add_warning(
      drop_percent(stats) > @drop_percent_threshold,
      "Capture drops exceed #{@drop_percent_threshold}%."
    )
    |> maybe_add_warning(
      field(stats, :bpf_restart_pending) == true,
      "BPF restart is pending."
    )
  end

  defp forwarding_warnings(:disabled, sink_count, _enabled_count) when sink_count > 0,
    do: ["All configured forwarding sinks are disabled."]

  defp forwarding_warnings(:no_data, sink_count, enabled_count)
       when sink_count > 0 and enabled_count > 0,
       do: ["Forwarding sink runtime telemetry is not available."]

  defp forwarding_warnings(:no_data, _sink_count, _enabled_count),
    do: ["Forwarding configuration or runtime telemetry is not available."]

  defp forwarding_warnings(_state, _sink_count, _enabled_count), do: []

  defp maybe_add_warning(warnings, true, warning), do: warnings ++ [warning]
  defp maybe_add_warning(warnings, _condition, _warning), do: warnings

  defp consumer_tooltip(name, stats) do
    %{
      name: to_string(name),
      packets_received: field(stats, :packets_received),
      packets_dropped: field(stats, :packets_dropped),
      drop_percent: field(stats, :drop_percent),
      throughput: format_throughput(field(stats, :throughput_bps)),
      bpf_restart_pending: field(stats, :bpf_restart_pending)
    }
  end

  defp maybe_add_pcap_metrics(tooltip, "pcap_ring", stats) do
    Map.merge(tooltip, %{
      packets_written: field(stats, :packets_written),
      bytes_written: field(stats, :bytes_written),
      bytes_written_label: format_bytes(field(stats, :bytes_written)),
      wrap_count: field(stats, :wrap_count),
      socket_drops: field(stats, :socket_drops),
      socket_freeze_queue_drops: field(stats, :socket_freeze_queue_drops),
      overwrite_risk: field(stats, :overwrite_risk)
    })
  end

  defp maybe_add_pcap_metrics(tooltip, _segment_id, _stats), do: tooltip

  defp sink_tooltip(sink) do
    config = decode_config(field(sink, :config))

    %{
      name: display(field(sink, :name)),
      sink_type: display(field(sink, :sink_type)),
      enabled: truthy?(field(sink, :enabled)),
      destination_label: destination_label(config),
      last_test_at: field(sink, :last_test_at),
      last_test_result: safe_last_test_result(field(sink, :last_test_result))
    }
  end

  defp decode_config(config) when is_binary(config) do
    case Jason.decode(config) do
      {:ok, decoded} when is_map(decoded) -> decoded
      _ -> %{}
    end
  end

  defp decode_config(config) when is_map(config), do: config
  defp decode_config(_config), do: %{}

  defp destination_label(config) do
    safe_keys = [
      "endpoint",
      "url",
      "host",
      "hosts",
      "path_template",
      "bucket",
      "topic",
      "bootstrap_servers"
    ]

    safe_keys
    |> Enum.find_value(fn key ->
      config
      |> Map.get(key)
      |> safe_destination_value()
    end)
    |> display()
  end

  defp safe_destination_value(nil), do: nil
  defp safe_destination_value(value) when is_binary(value), do: redact_secretish(value)

  defp safe_destination_value(value) when is_list(value),
    do: value |> Enum.map(&to_string/1) |> Enum.join(", ") |> redact_secretish()

  defp safe_destination_value(value), do: value |> to_string() |> redact_secretish()

  defp safe_last_test_result(nil), do: nil

  defp safe_last_test_result(result) when is_binary(result) do
    case Jason.decode(result) do
      {:ok, decoded} -> safe_last_test_result(decoded)
      _ -> nil
    end
  end

  defp safe_last_test_result(result) when is_map(result) do
    result
    |> Map.take([
      "result",
      "message",
      "endpoint",
      "error_category",
      :result,
      :message,
      :endpoint,
      :error_category
    ])
    |> Enum.map(fn {key, value} -> {key, safe_destination_value(value)} end)
    |> Map.new()
  end

  defp safe_last_test_result(_result), do: nil

  defp redact_secretish(value) when is_binary(value) do
    value
    |> String.replace(
      ~r/(?i)(token|password|secret|apikey|api_key|authorization)=([^&\s]+)/,
      "\\1=[redacted]"
    )
    |> String.replace(~r/(?i)(https?:\/\/[^:\s]+):([^@\s]+)@/, "\\1:[redacted]@")
  end

  defp field(data, key, default \\ nil)
  defp field(nil, _key, default), do: default

  defp field(data, key, default) when is_map(data) and is_atom(key) do
    cond do
      Map.has_key?(data, key) -> Map.get(data, key)
      Map.has_key?(data, Atom.to_string(key)) -> Map.get(data, Atom.to_string(key))
      true -> default
    end
  end

  defp field(data, key, default) when is_map(data), do: Map.get(data, key, default)
  defp field(_data, _key, default), do: default

  defp string_field(data, key) do
    data
    |> field(key)
    |> case do
      nil -> nil
      value -> to_string(value)
    end
  end

  defp present_string(nil), do: nil

  defp present_string(value) do
    value
    |> to_string()
    |> String.trim()
    |> case do
      "" -> nil
      string -> string
    end
  end

  defp display(nil), do: @dash
  defp display(""), do: @dash
  defp display(value), do: to_string(value)

  defp availability_label(true), do: "available"
  defp availability_label(false), do: "unavailable"
  defp availability_label(_), do: @dash

  defp container_state(nil), do: nil
  defp container_state(container), do: container |> field(:state) |> present_string()

  defp drop_percent(stats), do: numeric(field(stats, :drop_percent), 0.0)

  defp max_drop_percent([]), do: nil

  defp max_drop_percent(consumers) do
    consumers
    |> Enum.map(fn {_name, stats} -> drop_percent(stats) end)
    |> Enum.max(fn -> nil end)
  end

  defp aggregate_throughput([]), do: nil

  defp aggregate_throughput(consumers) do
    values =
      consumers
      |> Enum.map(fn {_name, stats} -> numeric(field(stats, :throughput_bps)) end)
      |> Enum.reject(&is_nil/1)

    case values do
      [] -> nil
      # Interface-backed consumers can each report the same physical rx_bytes
      # stream. Use the largest branch as the ingress estimate so fan-out does
      # not double-count Mirror Port -> AF_PACKET traffic.
      _ -> Enum.max(values)
    end
  end

  defp numeric(value, default \\ nil)
  defp numeric(value, _default) when is_number(value), do: value
  defp numeric(_value, default), do: default

  defp truthy?(value), do: value in [true, "true", "1", 1, "on"]

  defp state_counts(states) do
    base = Map.new(@segment_states, &{&1, 0})

    Enum.reduce(states, base, fn state, counts ->
      Map.update!(counts, state, &(&1 + 1))
    end)
  end

  defp aggregate_badges(state_counts) do
    [
      state_count_badge(state_counts, :no_data, "no data"),
      state_count_badge(state_counts, :failed, "failed"),
      state_count_badge(state_counts, :degraded, "degraded"),
      state_count_badge(state_counts, :pending_reload, "pending")
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp state_count_badge(counts, state, label) do
    count = Map.get(counts, state, 0)
    if count > 0, do: %{kind: :"#{state}_count", label: "#{count} #{label}"}
  end

  defp segment_by_id(pipeline_state, segment_id) do
    pipeline_state
    |> Map.get(:segments, [])
    |> Enum.find(&(&1.id == segment_id))
  end

  defp segment_state(segment),
    do: Map.get(segment, :state) || Map.get(segment, :overall_state) || :no_data

  defp summary_row(segment) do
    %{
      segment: segment.label,
      state: state_label(segment.state),
      throughput:
        Map.get(segment.metrics, :throughput) || Map.get(segment.metrics, :aggregate_throughput) ||
          @dash,
      details: summary_details(segment)
    }
  end

  defp aggregate_summary_row(segment) do
    %{
      segment: segment.label,
      overall_state: state_label(segment.overall_state),
      healthy: segment.state_counts.healthy,
      degraded: segment.state_counts.degraded,
      failed: segment.state_counts.failed,
      pending_reload: segment.state_counts.pending_reload,
      disabled: segment.state_counts.disabled,
      no_data: segment.state_counts.no_data
    }
  end

  defp summary_details(segment) do
    cond do
      Map.has_key?(segment.metrics, :consumer_count) ->
        "#{segment.metrics.consumer_count} consumers"

      Map.has_key?(segment.metrics, :sink_count) ->
        "#{segment.metrics.enabled_count}/#{segment.metrics.sink_count} sinks enabled"

      Map.has_key?(segment.metrics, :container_state) ->
        "container #{display(segment.metrics.container_state)}"

      true ->
        segment.warnings |> List.first() |> display()
    end
  end

  defp segment_summary(label, state, metrics, warnings, badges) do
    parts =
      [
        "#{label}: #{state_label(state)}",
        if(Map.has_key?(metrics, :aggregate_throughput),
          do: "throughput #{metrics.aggregate_throughput}"
        ),
        if(Map.has_key?(metrics, :throughput), do: "throughput #{metrics.throughput}"),
        if(Map.has_key?(metrics, :consumer_count), do: "#{metrics.consumer_count} consumers"),
        badges |> Enum.map(& &1.label) |> Enum.join(", "),
        List.first(warnings)
      ]
      |> Enum.reject(&blank?/1)

    Enum.join(parts, ". ")
  end

  defp aggregate_summary(label, state, counts) do
    count_summary =
      @segment_states
      |> Enum.map(fn state -> {state, Map.get(counts, state, 0)} end)
      |> Enum.reject(fn {_state, count} -> count == 0 end)
      |> Enum.map(fn {state, count} -> "#{count} #{state_label(state)}" end)
      |> Enum.join(", ")

    "#{label}: #{state_label(state)} overall. #{count_summary}."
  end

  defp connector_summary(source_label, target_label, throughput_label, nil, flow_state) do
    "#{source_label} to #{target_label}: #{throughput_label}, #{flow_state_label(flow_state)}."
  end

  defp connector_summary(
         source_label,
         target_label,
         throughput_label,
         secondary_label,
         flow_state
       ) do
    "#{source_label} to #{target_label}: #{throughput_label}, #{secondary_label}, #{flow_state_label(flow_state)}."
  end

  defp state_label(:healthy), do: "Healthy"
  defp state_label(:degraded), do: "Degraded"
  defp state_label(:failed), do: "Failed"
  defp state_label(:disabled), do: "Disabled"
  defp state_label(:pending_reload), do: "Pending Reload"
  defp state_label(:no_data), do: "No Data"
  defp state_label(state), do: state |> to_string() |> String.replace("_", " ")

  defp flow_state_label(:flowing), do: "flowing"
  defp flow_state_label(:degraded), do: "degraded flow"
  defp flow_state_label(:idle), do: "idle"
  defp flow_state_label(:stopped), do: "stopped"
  defp flow_state_label(:unknown), do: "unknown flow"

  defp reason_label(reason), do: reason |> to_string() |> String.replace("_", " ")

  defp stale_message(nil), do: "Health data is stale; report age is unknown."
  defp stale_message(age), do: "Health data is stale; last report was #{age} seconds ago."

  defp storage_used_label(nil), do: @dash
  defp storage_used_label(percent) when is_number(percent), do: decimal(percent) <> "%"

  defp maybe_unknown_secondary_label(connector, nil), do: connector
  defp maybe_unknown_secondary_label(connector, _name), do: connector

  defp report_datetime(timestamp_unix_ms)
       when is_integer(timestamp_unix_ms) and timestamp_unix_ms > 0 do
    case DateTime.from_unix(timestamp_unix_ms, :millisecond) do
      {:ok, datetime} -> datetime
      _ -> nil
    end
  end

  defp report_datetime(_), do: nil

  defp format_bytes(nil), do: @dash
  defp format_bytes(bytes) when not is_number(bytes) or bytes < 0, do: @dash
  defp format_bytes(0), do: "0 B"

  defp format_bytes(bytes) do
    cond do
      bytes >= 1_099_511_627_776 -> decimal(bytes / 1_099_511_627_776) <> " TB"
      bytes >= 1_073_741_824 -> decimal(bytes / 1_073_741_824) <> " GB"
      bytes >= 1_048_576 -> decimal(bytes / 1_048_576) <> " MB"
      bytes >= 1_024 -> decimal(bytes / 1_024) <> " KB"
      true -> "#{round(bytes)} B"
    end
  end

  defp decimal(value), do: :erlang.float_to_binary(value / 1, decimals: 1)

  defp format_rate(rate) when rate >= 1_000_000, do: decimal(rate / 1_000_000) <> "m"
  defp format_rate(rate) when rate >= 1_000, do: decimal(rate / 1_000) <> "k"
  defp format_rate(rate), do: decimal(rate)

  defp comma_integer(integer) do
    integer
    |> Integer.to_string()
    |> String.reverse()
    |> String.graphemes()
    |> Enum.chunk_every(3)
    |> Enum.map(&Enum.join/1)
    |> Enum.join(",")
    |> String.reverse()
  end

  defp normalize_name(name) do
    name
    |> to_string()
    |> String.trim()
    |> String.downcase()
  end

  defp sanitize_id(name) do
    name
    |> normalize_name()
    |> String.replace(~r/[^a-z0-9_-]+/, "-")
    |> String.trim("-")
    |> case do
      "" -> "unnamed"
      value -> value
    end
  end

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?(_), do: false
end
