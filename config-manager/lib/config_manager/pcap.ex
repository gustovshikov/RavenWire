defmodule ConfigManager.Pcap do
  @moduledoc "PCAP carve request lifecycle and chain-of-custody context."

  import Ecto.Query

  alias ConfigManager.Auth.ApiToken
  alias ConfigManager.Pcap.{CarveRequest, CustodyEvent}
  alias ConfigManager.{Audit, Repo, SensorAgentClient, SensorPod}
  alias Ecto.Multi

  @max_range_seconds 24 * 60 * 60
  @retention_hours 72

  def submit_carve(params, actor, client \\ SensorAgentClient) do
    with {:ok, pod} <- fetch_pod(params),
         {:ok, search_type, search_params} <- normalize_search(params),
         {:ok, request} <- create_request(pod, search_type, search_params, actor) do
      log_search(request)
      dispatch_carve(request, client)
    end
  end

  def dispatch_carve(%CarveRequest{} = request, client \\ SensorAgentClient) do
    request = Repo.preload(request, :sensor_pod)

    case client.request_pcap_carve(request.sensor_pod, carve_payload(request)) do
      {:ok, response} ->
        status = response |> response_value("status") |> agent_status()
        metadata = status_metadata(response)

        case update_status(request, status, metadata) do
          {:ok, updated} ->
            log_dispatch(updated)
            {:ok, updated}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        failed = fail_request(request, failure_reason(reason))
        {:error, {failure_code(reason), failed}}
    end
  end

  def update_status(%CarveRequest{} = request, status, attrs \\ %{}) do
    attrs = normalize_status_attrs(status, attrs)

    Multi.new()
    |> Multi.update(:request, CarveRequest.status_changeset(request, status, attrs))
    |> maybe_insert_created_event(status)
    |> Repo.transaction()
    |> case do
      {:ok, %{request: updated}} ->
        log_status_transition(updated, status)
        {:ok, Repo.preload(updated, [:sensor_pod, :custody_events])}

      {:error, :request, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def fail_request(%CarveRequest{} = request, reason) do
    {:ok, failed} = update_status(request, "failed", %{error_reason: reason})
    failed
  end

  def list_requests(params \\ %{}) do
    page = max(int_param(params, "page", 1), 1)
    page_size = max(int_param(params, "page_size", 25), 1)

    query =
      CarveRequest
      |> maybe_filter(:status, param(params, "status"))
      |> maybe_filter(:sensor_pod_id, param(params, "sensor_pod_id"))
      |> maybe_filter(:search_type, param(params, "search_type"))

    total_count = Repo.aggregate(query, :count, :id)

    entries =
      query
      |> order_by([r], desc: r.inserted_at)
      |> limit(^page_size)
      |> offset(^((page - 1) * page_size))
      |> preload([:sensor_pod])
      |> Repo.all()

    %{
      entries: entries,
      page: page,
      page_size: page_size,
      total_count: total_count,
      total_pages: total_pages(total_count, page_size)
    }
  end

  def get_request(id) do
    CarveRequest
    |> preload([:sensor_pod, :custody_events])
    |> Repo.get(id)
  end

  def get_request!(id) do
    CarveRequest
    |> preload([:sensor_pod, :custody_events])
    |> Repo.get!(id)
  end

  def manifest(%CarveRequest{} = request) do
    request = Repo.preload(request, [:sensor_pod, :custody_events])

    events =
      request.custody_events
      |> Enum.sort_by(&DateTime.to_unix(&1.timestamp, :microsecond))
      |> Enum.map(&custody_event_json/1)

    content = %{
      request: request_json(request),
      custody_events: events
    }

    Map.put(content, :integrity_hash, integrity_hash(content))
  end

  def export_manifest_json(%CarveRequest{} = request, actor, client_ip \\ nil) do
    {:ok, _event} =
      create_custody_event(request, "manifest_exported", actor, %{
        client_ip: client_ip,
        detail: %{format: "json"}
      })

    log_manifest_export(request, actor)
    manifest = manifest(request)
    {:ok, Jason.encode!(manifest), manifest.integrity_hash}
  end

  def download_pcap(%CarveRequest{} = request, actor, client_ip, client \\ SensorAgentClient) do
    request = Repo.preload(request, :sensor_pod)

    cond do
      request.status != "completed" ->
        {:error, :not_ready}

      expired?(request) ->
        {:ok, expired} = update_status(request, "expired")
        {:error, {:expired, expired}}

      true ->
        case client.download_pcap_carve(request.sensor_pod, request.id) do
          {:ok, download} ->
            {:ok, _event} =
              create_custody_event(request, "downloaded", actor, %{
                client_ip: client_ip,
                detail: %{sha256: request.sha256, file_size_bytes: request.file_size_bytes}
              })

            log_download(request, actor, client_ip)

            {:ok,
             %{
               body: Map.get(download, :body, ""),
               content_type:
                 Map.get(download, :content_type) || content_type_for_path(request.file_path),
               filename: download_filename(request)
             }}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  def request_json(%CarveRequest{} = request) do
    %{
      id: request.id,
      actor: request.actor,
      actor_type: request.actor_type,
      user_id: request.user_id,
      search_type: request.search_type,
      search_params: request.search_params,
      sensor_pod_id: request.sensor_pod_id,
      sensor_name: request.sensor_name,
      status: request.status,
      error_reason: request.error_reason,
      file_path: request.file_path,
      file_size_bytes: request.file_size_bytes,
      sha256: request.sha256,
      packet_count: request.packet_count,
      time_span_start: request.time_span_start,
      time_span_end: request.time_span_end,
      expires_at: request.expires_at,
      inserted_at: request.inserted_at,
      updated_at: request.updated_at
    }
  end

  def download_filename(%CarveRequest{} = request) do
    timestamp =
      request.inserted_at
      |> case do
        nil -> DateTime.utc_now()
        value -> value
      end
      |> Calendar.strftime("%Y%m%d%H%M%S")

    sensor =
      request.sensor_name
      |> to_string()
      |> String.replace(~r/[^A-Za-z0-9_.-]+/, "-")
      |> String.trim("-")

    "#{sensor}-#{request.search_type}-#{timestamp}.pcap"
  end

  def expired?(%CarveRequest{expires_at: nil}), do: false

  def expired?(%CarveRequest{expires_at: expires_at}) do
    DateTime.compare(expires_at, DateTime.utc_now()) != :gt
  end

  defp fetch_pod(params) do
    case param(params, "pod_id") || param(params, "sensor_pod_id") do
      nil ->
        {:error, {:validation, %{pod_id: ["is required"]}}}

      pod_id ->
        case Repo.get(SensorPod, pod_id) do
          nil -> {:error, :not_found}
          %SensorPod{} = pod -> {:ok, pod}
        end
    end
  end

  defp normalize_search(params) do
    search_type = params |> param("search_type") |> infer_search_type(params)

    cond do
      search_type not in CarveRequest.search_types() ->
        {:error, {:validation, %{search_type: ["is invalid"]}}}

      true ->
        params = normalize_param_map(params)
        search_params = Map.drop(params, ["pod_id", "sensor_pod_id"])

        case validate_search_params(search_type, search_params) do
          :ok -> {:ok, search_type, search_params}
          {:error, errors} -> {:error, {:validation, errors}}
        end
    end
  end

  defp create_request(%SensorPod{} = pod, search_type, search_params, actor) do
    attrs = %{
      user_id: actor_user_id(actor),
      actor: actor_name(actor),
      actor_type: actor_type(actor),
      search_type: search_type,
      search_params: search_params,
      sensor_pod_id: pod.id,
      sensor_name: pod.name,
      status: "pending"
    }

    %CarveRequest{}
    |> CarveRequest.create_changeset(attrs)
    |> Repo.insert()
  end

  defp validate_search_params("time_range", params) do
    %{}
    |> require_fields(params, ["start_time", "end_time"])
    |> validate_time_range(params)
    |> validation_result()
  end

  defp validate_search_params("community_id", params) do
    %{}
    |> require_fields(params, ["community_id"])
    |> validate_community_id(params)
    |> validate_time_range(params)
    |> validation_result()
  end

  defp validate_search_params("five_tuple", params) do
    %{}
    |> require_fields(params, ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"])
    |> validate_ip(params, "src_ip")
    |> validate_ip(params, "dst_ip")
    |> validate_port(params, "src_port")
    |> validate_port(params, "dst_port")
    |> validate_time_range(params)
    |> validation_result()
  end

  defp validate_search_params("alert_id", params) do
    %{}
    |> require_one(params, ["alert_id", "sid"])
    |> validate_time_range(params)
    |> validation_result()
  end

  defp validate_search_params("zeek_uid", params) do
    %{}
    |> require_fields(params, ["zeek_uid"])
    |> validate_time_range(params)
    |> validation_result()
  end

  defp require_fields(errors, params, fields) do
    Enum.reduce(fields, errors, fn field, acc ->
      if present?(Map.get(params, field)), do: acc, else: add_error(acc, field, "is required")
    end)
  end

  defp require_one(errors, params, fields) do
    if Enum.any?(fields, &present?(Map.get(params, &1))) do
      errors
    else
      add_error(errors, hd(fields), "one of #{Enum.join(fields, ", ")} is required")
    end
  end

  defp validate_community_id(errors, params) do
    community_id = Map.get(params, "community_id")

    if present?(community_id) and not Regex.match?(~r/^1:[A-Za-z0-9+\/_-]+=*$/, community_id) do
      add_error(errors, "community_id", "has invalid format")
    else
      errors
    end
  end

  defp validate_ip(errors, params, field) do
    value = Map.get(params, field)

    if present?(value) do
      case value |> to_charlist() |> :inet.parse_address() do
        {:ok, _ip} -> errors
        {:error, _reason} -> add_error(errors, field, "is invalid")
      end
    else
      errors
    end
  end

  defp validate_port(errors, params, field) do
    value = int_value(Map.get(params, field))

    if is_integer(value) and value in 0..65_535 do
      errors
    else
      add_error(errors, field, "must be between 0 and 65535")
    end
  end

  defp validate_time_range(errors, params) do
    start_time = Map.get(params, "start_time")
    end_time = Map.get(params, "end_time")

    cond do
      not present?(start_time) and not present?(end_time) ->
        errors

      not present?(start_time) or not present?(end_time) ->
        errors
        |> maybe_add_missing_time("start_time", start_time)
        |> maybe_add_missing_time("end_time", end_time)

      true ->
        with {:ok, start_dt} <- parse_datetime(start_time),
             {:ok, end_dt} <- parse_datetime(end_time) do
          duration = DateTime.diff(end_dt, start_dt, :second)

          cond do
            duration <= 0 ->
              add_error(errors, "end_time", "must be after start_time")

            duration > @max_range_seconds ->
              add_error(errors, "end_time", "range exceeds 24 hours")

            true ->
              errors
          end
        else
          {:error, field} -> add_error(errors, field, "is invalid")
        end
    end
  end

  defp maybe_add_missing_time(errors, field, value) do
    if present?(value), do: errors, else: add_error(errors, field, "is required")
  end

  defp validation_result(errors) when errors == %{}, do: :ok
  defp validation_result(errors), do: {:error, errors}

  defp carve_payload(%CarveRequest{} = request) do
    %{
      request_id: request.id,
      search_type: request.search_type,
      params: request.search_params,
      start_time: Map.get(request.search_params || %{}, "start_time"),
      end_time: Map.get(request.search_params || %{}, "end_time")
    }
  end

  defp normalize_status_attrs("completed", attrs) do
    attrs
    |> take_status_attrs()
    |> Map.put_new(:expires_at, DateTime.add(DateTime.utc_now(), retention_hours(), :hour))
  end

  defp normalize_status_attrs(_status, attrs), do: take_status_attrs(attrs)

  defp take_status_attrs(attrs) do
    attrs
    |> normalize_param_map()
    |> Map.take([
      "error_reason",
      "file_path",
      "file_size_bytes",
      "sha256",
      "packet_count",
      "time_span_start",
      "time_span_end",
      "expires_at"
    ])
    |> Enum.map(fn
      {key, value} when key in ["time_span_start", "time_span_end", "expires_at"] ->
        {String.to_atom(key), parse_datetime_value(value)}

      {key, value} when key in ["file_size_bytes", "packet_count"] ->
        {String.to_atom(key), int_value(value)}

      {key, value} ->
        {String.to_atom(key), value}
    end)
    |> Map.new()
  end

  defp maybe_insert_created_event(multi, "completed") do
    Multi.insert(multi, :custody_event, fn %{request: request} ->
      CustodyEvent.changeset(%CustodyEvent{}, created_event_attrs(request))
    end)
  end

  defp maybe_insert_created_event(multi, _status), do: multi

  defp created_event_attrs(%CarveRequest{} = request) do
    %{
      carve_request_id: request.id,
      event_type: "created",
      actor_username: request.actor,
      actor_display_name: request.actor,
      detail: %{
        request_id: request.id,
        sensor_pod_id: request.sensor_pod_id,
        sensor_name: request.sensor_name,
        search_type: request.search_type,
        search_params: request.search_params,
        sha256: request.sha256,
        file_size_bytes: request.file_size_bytes,
        packet_count: request.packet_count,
        time_span_start: request.time_span_start,
        time_span_end: request.time_span_end
      },
      timestamp: DateTime.utc_now()
    }
  end

  defp create_custody_event(request, event_type, actor, attrs) do
    attrs =
      %{
        carve_request_id: request.id,
        event_type: event_type,
        actor_username: actor_name(actor),
        actor_display_name: actor_display_name(actor),
        client_ip: Map.get(attrs, :client_ip),
        detail: Map.get(attrs, :detail, %{}),
        timestamp: DateTime.utc_now()
      }

    %CustodyEvent{}
    |> CustodyEvent.changeset(attrs)
    |> Repo.insert()
  end

  defp custody_event_json(%CustodyEvent{} = event) do
    %{
      id: event.id,
      event_type: event.event_type,
      actor_username: event.actor_username,
      actor_display_name: event.actor_display_name,
      client_ip: event.client_ip,
      detail: event.detail,
      timestamp: event.timestamp
    }
  end

  defp log_search(%CarveRequest{} = request) do
    Audit.log(%{
      actor: request.actor,
      actor_type: request.actor_type,
      action: "pcap_search",
      target_type: "sensor_pod",
      target_id: request.sensor_pod_id,
      result: "success",
      detail: %{
        request_id: request.id,
        search_type: request.search_type,
        search_params: request.search_params,
        required_permission: "pcap:search"
      }
    })
  end

  defp log_dispatch(%CarveRequest{} = request) do
    Audit.log(%{
      actor: request.actor,
      actor_type: request.actor_type,
      action: "pcap_carve_dispatch",
      target_type: "pcap_carve_request",
      target_id: request.id,
      result: "success",
      detail: %{
        sensor_pod_id: request.sensor_pod_id,
        sensor_name: request.sensor_name,
        search_type: request.search_type,
        required_permission: "pcap:search"
      }
    })
  end

  defp log_status_transition(%CarveRequest{} = request, "completed") do
    Audit.log(%{
      actor: request.actor,
      actor_type: request.actor_type,
      action: "pcap_carve_complete",
      target_type: "pcap_carve_request",
      target_id: request.id,
      result: "success",
      detail: %{
        file_size_bytes: request.file_size_bytes,
        sha256: request.sha256,
        packet_count: request.packet_count
      }
    })
  end

  defp log_status_transition(%CarveRequest{} = request, "failed") do
    Audit.log(%{
      actor: request.actor,
      actor_type: request.actor_type,
      action: "pcap_carve_failed",
      target_type: "pcap_carve_request",
      target_id: request.id,
      result: "failure",
      detail: %{reason: request.error_reason}
    })
  end

  defp log_status_transition(_request, _status), do: :ok

  defp log_download(request, actor, client_ip) do
    Audit.log(%{
      actor: actor_name(actor),
      actor_type: actor_type(actor),
      action: "pcap_download",
      target_type: "pcap_carve_request",
      target_id: request.id,
      result: "success",
      detail: %{
        sha256: request.sha256,
        file_size_bytes: request.file_size_bytes,
        client_ip: client_ip,
        required_permission: "pcap:download"
      }
    })
  end

  defp log_manifest_export(request, actor) do
    Audit.log(%{
      actor: actor_name(actor),
      actor_type: actor_type(actor),
      action: "pcap_manifest_export",
      target_type: "pcap_carve_request",
      target_id: request.id,
      result: "success",
      detail: %{format: "json", required_permission: "pcap:search"}
    })
  end

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, _field, ""), do: query

  defp maybe_filter(query, field, value) do
    where(query, [r], field(r, ^field) == ^value)
  end

  defp status_metadata(response) when is_map(response) do
    %{
      file_path: response_value(response, "file_path"),
      file_size_bytes: response_value(response, "file_size_bytes"),
      sha256: response_value(response, "sha256"),
      packet_count: response_value(response, "packet_count"),
      time_span_start: response_value(response, "time_span_start"),
      time_span_end: response_value(response, "time_span_end"),
      error_reason: response_value(response, "error")
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
    |> Map.new()
  end

  defp status_metadata(_response), do: %{}

  defp response_value(map, key), do: Map.get(map, key) || Map.get(map, String.to_atom(key))

  defp agent_status(nil), do: "dispatched"
  defp agent_status("queued"), do: "dispatched"
  defp agent_status("dispatched"), do: "dispatched"
  defp agent_status("carving"), do: "carving"
  defp agent_status("completed"), do: "completed"
  defp agent_status("failed"), do: "failed"
  defp agent_status(_status), do: "dispatched"

  defp failure_reason(:no_control_api_host), do: "sensor_unreachable"
  defp failure_reason({:validation_error, detail}), do: inspect(detail)
  defp failure_reason({:http_error, status, body}), do: "HTTP #{status}: #{body}"
  defp failure_reason(reason), do: inspect(reason)

  defp failure_code(:no_control_api_host), do: :sensor_unreachable
  defp failure_code({:validation_error, _detail}), do: :validation_error
  defp failure_code(_reason), do: :dispatch_failed

  defp retention_hours do
    case System.get_env("RAVENWIRE_PCAP_RETENTION_HOURS") do
      nil -> @retention_hours
      value -> max(int_value(value) || @retention_hours, 1)
    end
  end

  defp param(params, key) when is_map(params) do
    Map.get(params, key) || Map.get(params, String.to_atom(key))
  end

  defp infer_search_type(nil, params) do
    cond do
      present?(param(params, "community_id")) -> "community_id"
      present?(param(params, "src_ip")) -> "five_tuple"
      present?(param(params, "alert_id")) or present?(param(params, "sid")) -> "alert_id"
      present?(param(params, "zeek_uid")) -> "zeek_uid"
      true -> "time_range"
    end
  end

  defp infer_search_type(search_type, _params), do: to_string(search_type)

  defp normalize_param_map(params) when is_map(params) do
    Map.new(params, fn {key, value} -> {to_string(key), normalize_value(value)} end)
  end

  defp normalize_param_map(_params), do: %{}

  defp normalize_value(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp normalize_value(value) when is_map(value), do: normalize_param_map(value)
  defp normalize_value(value) when is_list(value), do: Enum.map(value, &normalize_value/1)
  defp normalize_value(value), do: value

  defp add_error(errors, field, message),
    do: Map.update(errors, field, [message], &[message | &1])

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(_value), do: true

  defp parse_datetime(value) do
    case parse_datetime_value(value) do
      %DateTime{} = datetime -> {:ok, datetime}
      nil -> {:error, "start_time"}
    end
  end

  defp parse_datetime_value(%DateTime{} = value), do: DateTime.truncate(value, :microsecond)

  defp parse_datetime_value(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> DateTime.truncate(datetime, :microsecond)
      {:error, _reason} -> nil
    end
  end

  defp parse_datetime_value(_value), do: nil

  defp int_param(params, key, default), do: int_value(param(params, key)) || default

  defp int_value(value) when is_integer(value), do: value

  defp int_value(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, _rest} -> integer
      :error -> nil
    end
  end

  defp int_value(_value), do: nil

  defp total_pages(0, _page_size), do: 0
  defp total_pages(total_count, page_size), do: div(total_count + page_size - 1, page_size)

  defp content_type_for_path(path) when is_binary(path) do
    if String.ends_with?(path, ".pcapng"),
      do: "application/octet-stream",
      else: "application/vnd.tcpdump.pcap"
  end

  defp content_type_for_path(_path), do: "application/vnd.tcpdump.pcap"

  defp integrity_hash(content) do
    content
    |> Jason.encode!()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp actor_user_id(%ApiToken{user_id: user_id}), do: user_id
  defp actor_user_id(%{id: id}), do: id
  defp actor_user_id(_actor), do: nil

  defp actor_name(%ApiToken{name: name}), do: name
  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor), do: actor
  defp actor_name(_actor), do: "system"

  defp actor_display_name(%ApiToken{user: %{display_name: display_name}})
       when not is_nil(display_name),
       do: display_name

  defp actor_display_name(%ApiToken{name: name}), do: name

  defp actor_display_name(%{display_name: display_name}) when not is_nil(display_name),
    do: display_name

  defp actor_display_name(actor), do: actor_name(actor)

  defp actor_type(%ApiToken{}), do: "api_token"
  defp actor_type(%{username: _username}), do: "user"
  defp actor_type("system"), do: "system"
  defp actor_type(_actor), do: "system"
end
