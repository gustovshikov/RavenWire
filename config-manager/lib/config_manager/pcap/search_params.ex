defmodule ConfigManager.Pcap.SearchParams do
  @moduledoc "Validation and normalization for PCAP search parameters."

  alias ConfigManager.Pcap.{CarveRequest, CommunityId}

  @max_range_seconds 24 * 60 * 60
  @selector_keys ~w(pod_id sensor_pod_id sensor_pod_ids sensors _csrf_token)

  defstruct [:search_type, :search_params, :sensor_pod_ids]

  @type t :: %__MODULE__{
          search_type: String.t(),
          search_params: map(),
          sensor_pod_ids: [String.t()]
        }

  @doc "Validates raw PCAP search params and returns normalized search params."
  @spec validate(map()) :: {:ok, t()} | {:error, map()}
  def validate(params) when is_map(params) do
    normalized = normalize_param_map(params)
    search_type = normalized |> Map.get("search_type") |> infer_search_type(normalized)
    search_params = Map.drop(normalized, @selector_keys)

    cond do
      search_type not in CarveRequest.search_types() ->
        {:error, %{search_type: ["is invalid"]}}

      true ->
        case validate_search_params(search_type, search_params) do
          :ok ->
            {:ok,
             %__MODULE__{
               search_type: search_type,
               search_params: Map.put(search_params, "search_type", search_type),
               sensor_pod_ids: sensor_ids(normalized)
             }}

          {:error, errors} ->
            {:error, errors}
        end
    end
  end

  def validate(_params), do: {:error, %{search_type: ["is required"]}}

  @doc "Converts validated params to the Sensor Agent carve payload."
  @spec to_carve_payload(t(), String.t() | nil) :: map()
  def to_carve_payload(%__MODULE__{} = params, request_id \\ nil) do
    %{
      request_id: request_id,
      search_type: params.search_type,
      params: Map.delete(params.search_params || %{}, "search_type"),
      start_time: Map.get(params.search_params || %{}, "start_time"),
      end_time: Map.get(params.search_params || %{}, "end_time")
    }
  end

  @doc false
  def normalize_param_map(params) when is_map(params) do
    params
    |> Map.new(fn {key, value} -> {to_string(key), normalize_value(value)} end)
    |> reject_blank_optional_values()
  end

  def normalize_param_map(_params), do: %{}

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
    |> validate_protocol(params)
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

    if present?(community_id) and not CommunityId.valid_format?(community_id) do
      add_error(errors, "community_id", "has invalid format")
    else
      errors
    end
  end

  defp validate_ip(errors, params, field) do
    value = Map.get(params, field)

    if present?(value) do
      case CommunityId.parse_ip(value) do
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

  defp validate_protocol(errors, params) do
    value = Map.get(params, "protocol")

    case CommunityId.protocol_number(value) do
      {:ok, _protocol} -> errors
      {:error, _reason} -> add_error(errors, "protocol", "is invalid")
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
        with {:ok, start_dt} <- parse_datetime(start_time, "start_time"),
             {:ok, end_dt} <- parse_datetime(end_time, "end_time") do
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

  defp infer_search_type(nil, params) do
    cond do
      present?(Map.get(params, "community_id")) -> "community_id"
      present?(Map.get(params, "src_ip")) -> "five_tuple"
      present?(Map.get(params, "alert_id")) or present?(Map.get(params, "sid")) -> "alert_id"
      present?(Map.get(params, "zeek_uid")) -> "zeek_uid"
      true -> "time_range"
    end
  end

  defp infer_search_type(search_type, _params), do: to_string(search_type)

  defp sensor_ids(params) do
    params
    |> Map.take(["pod_id", "sensor_pod_id", "sensor_pod_ids", "sensors"])
    |> Map.values()
    |> List.flatten()
    |> Enum.map(&to_string/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp validation_result(errors) when errors == %{}, do: :ok
  defp validation_result(errors), do: {:error, errors}

  defp normalize_value(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp normalize_value(value) when is_map(value), do: normalize_param_map(value)
  defp normalize_value(value) when is_list(value), do: Enum.map(value, &normalize_value/1)
  defp normalize_value(value) when is_binary(value), do: String.trim(value)
  defp normalize_value(value), do: value

  defp reject_blank_optional_values(params) do
    Map.reject(params, fn {_key, value} -> value == "" or value == [] end)
  end

  defp add_error(errors, field, message),
    do: Map.update(errors, field, [message], &[message | &1])

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(_value), do: true

  defp parse_datetime(%DateTime{} = value, _field),
    do: {:ok, DateTime.truncate(value, :microsecond)}

  defp parse_datetime(value, field) when is_binary(value) do
    value
    |> normalize_datetime_string()
    |> DateTime.from_iso8601()
    |> case do
      {:ok, datetime, _offset} -> {:ok, DateTime.truncate(datetime, :microsecond)}
      {:error, _reason} -> {:error, field}
    end
  end

  defp parse_datetime(_value, field), do: {:error, field}

  defp normalize_datetime_string(value) do
    cond do
      String.ends_with?(value, "Z") or Regex.match?(~r/[+-]\d{2}:\d{2}$/, value) ->
        value

      Regex.match?(~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/, value) ->
        value <> ":00Z"

      Regex.match?(~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/, value) ->
        value <> "Z"

      true ->
        value
    end
  end

  defp int_value(value) when is_integer(value), do: value

  defp int_value(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} -> integer
      _other -> nil
    end
  end

  defp int_value(_value), do: nil
end
