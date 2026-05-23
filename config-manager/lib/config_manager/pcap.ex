defmodule ConfigManager.Pcap do
  @moduledoc "PCAP carve request lifecycle and chain-of-custody context."

  import Ecto.Query

  alias ConfigManager.Auth.ApiToken
  alias ConfigManager.Health.Registry, as: HealthRegistry
  alias ConfigManager.Pcap.{CarveRequest, CustodyEvent, SearchParams}
  alias ConfigManager.{Audit, Repo, SensorAgentClient, SensorPod}
  alias Ecto.Multi

  @retention_hours 72

  def submit_carve(params, actor, client \\ SensorAgentClient) do
    with {:ok, pod} <- fetch_pod(params),
         {:ok, %SearchParams{} = search} <- validate_search(params),
         {:ok, request} <-
           create_request(pod, search.search_type, request_search_params(search), actor) do
      log_search(request)
      dispatch_carve(request, client)
    end
  end

  def submit_search(params, actor, client \\ SensorAgentClient) do
    with {:ok, %SearchParams{} = search} <- validate_search(params),
         {:ok, pods} <- resolve_target_pods(search.sensor_pod_ids) do
      requests =
        Enum.map(pods, fn pod ->
          {:ok, request} =
            create_request(pod, search.search_type, request_search_params(search), actor)

          log_search(request)
          dispatch_for_search(request, client)
        end)

      {:ok, requests}
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
    CarveRequest
    |> request_filters(params)
    |> paginate_requests(params)
  end

  def list_requests_for_actor(actor, params \\ %{}) do
    actor
    |> scoped_request_query()
    |> request_filters(params)
    |> paginate_requests(params)
  end

  def active_request_count(actor) do
    actor
    |> scoped_request_query()
    |> where([r], r.status not in ^CarveRequest.terminal_statuses())
    |> Repo.aggregate(:count, :id)
  end

  def get_request_for_actor(id, actor) do
    actor
    |> scoped_request_query()
    |> preload([:sensor_pod, :custody_events])
    |> Repo.get(id)
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

  def sensor_options do
    SensorPod
    |> where([p], p.status == "enrolled")
    |> order_by([p], asc: p.name)
    |> Repo.all()
    |> Enum.map(fn pod ->
      %{
        id: pod.id,
        name: pod.name,
        control_api_host: pod.control_api_host,
        online: online?(pod)
      }
    end)
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

  defp validate_search(params) do
    case SearchParams.validate(params) do
      {:ok, search} -> {:ok, search}
      {:error, errors} -> {:error, {:validation, errors}}
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

  defp request_search_params(%SearchParams{} = search) do
    Map.delete(search.search_params || %{}, "search_type")
  end

  defp dispatch_for_search(%CarveRequest{} = request, client) do
    case dispatch_carve(request, client) do
      {:ok, updated} ->
        updated

      {:error, {_code, %CarveRequest{} = failed}} ->
        failed

      {:error, _reason} ->
        request
    end
  end

  defp resolve_target_pods([]) do
    pods =
      SensorPod
      |> where([p], p.status == "enrolled")
      |> Repo.all()
      |> Enum.filter(&online?/1)

    if pods == [] do
      {:error, {:validation, %{sensor_pod_ids: ["select at least one online sensor"]}}}
    else
      {:ok, pods}
    end
  end

  defp resolve_target_pods(sensor_pod_ids) when is_list(sensor_pod_ids) do
    pods =
      SensorPod
      |> where([p], p.id in ^sensor_pod_ids and p.status == "enrolled")
      |> Repo.all()

    if length(pods) == length(Enum.uniq(sensor_pod_ids)) do
      {:ok, pods}
    else
      {:error, {:validation, %{sensor_pod_ids: ["contains unknown or unenrolled sensor"]}}}
    end
  end

  defp carve_payload(%CarveRequest{} = request) do
    %SearchParams{search_type: request.search_type, search_params: request.search_params || %{}}
    |> SearchParams.to_carve_payload(request.id)
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

  defp scoped_request_query(%{role: "platform-admin"}), do: CarveRequest
  defp scoped_request_query(%ApiToken{}), do: CarveRequest

  defp scoped_request_query(%{id: user_id}) do
    where(CarveRequest, [r], r.user_id == ^user_id)
  end

  defp scoped_request_query(_actor), do: where(CarveRequest, [r], false)

  defp request_filters(query, params) do
    query
    |> maybe_filter(:status, param(params, "status"))
    |> maybe_filter(:sensor_pod_id, param(params, "sensor_pod_id"))
    |> maybe_filter(:sensor_name, param(params, "sensor_name"))
    |> maybe_filter(:search_type, param(params, "search_type"))
  end

  defp paginate_requests(query, params) do
    page = max(int_param(params, "page", 1), 1)
    page_size = max(int_param(params, "page_size", 25), 1)
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

  defp online?(%SensorPod{} = pod) do
    not is_nil(HealthRegistry.get_pod(pod.id)) or not is_nil(HealthRegistry.get_pod(pod.name))
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

  defp normalize_param_map(params) when is_map(params) do
    Map.new(params, fn {key, value} -> {to_string(key), normalize_value(value)} end)
  end

  defp normalize_param_map(_params), do: %{}

  defp normalize_value(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp normalize_value(value) when is_map(value), do: normalize_param_map(value)
  defp normalize_value(value) when is_list(value), do: Enum.map(value, &normalize_value/1)
  defp normalize_value(value), do: value

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
