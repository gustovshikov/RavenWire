defmodule ConfigManagerWeb.Api.Schemas do
  @moduledoc "Reusable OpenAPI schema components for implemented Public API endpoints."

  def components do
    %{
      "ErrorResponse" =>
        object(%{
          "error" =>
            object(
              %{
                "code" => string(),
                "message" => string(),
                "details" => %{"type" => "object", "additionalProperties" => true},
                "request_id" => string()
              },
              ["code", "message"]
            )
        }),
      "PaginationMeta" =>
        object(%{
          "page" => integer(),
          "page_size" => integer(),
          "total_count" => integer(),
          "total_pages" => integer()
        }),
      "Deployment" =>
        object(%{
          "id" => string(),
          "pool_id" => string(),
          "status" => string(),
          "operator" => string(),
          "operator_type" => string(),
          "config_version" => integer(),
          "forwarding_config_version" => integer(),
          "bpf_version" => integer(),
          "diff_summary" => %{"type" => "object", "additionalProperties" => true},
          "rollback_of_deployment_id" => nullable_string(),
          "source_deployment_id" => nullable_string(),
          "started_at" => date_time(),
          "completed_at" => date_time(),
          "failure_reason" => nullable_string(),
          "inserted_at" => date_time(),
          "updated_at" => date_time()
        }),
      "PcapConfig" =>
        object(%{
          "pod_id" => string(),
          "pcap_ring_size_mb" => integer(),
          "pre_alert_window_sec" => integer(),
          "post_alert_window_sec" => integer(),
          "alert_severity_threshold" => integer()
        }),
      "PcapRequest" =>
        object(%{
          "id" => string(),
          "sensor_pod_id" => string(),
          "search_type" => string(),
          "status" => string(),
          "actor" => string(),
          "actor_type" => string(),
          "error_reason" => nullable_string(),
          "expires_at" => date_time(),
          "inserted_at" => date_time(),
          "updated_at" => date_time()
        }),
      "PcapManifest" =>
        object(%{
          "request" => %{"$ref" => "#/components/schemas/PcapRequest"},
          "custody_events" => array(%{"type" => "object", "additionalProperties" => true}),
          "integrity_hash" => string()
        }),
      "Rule" =>
        object(%{
          "id" => string(),
          "sid" => integer(),
          "message" => string(),
          "category" => string(),
          "classtype" => nullable_string(),
          "severity" => integer(),
          "revision" => integer(),
          "enabled" => boolean(),
          "repository_id" => nullable_string(),
          "repository_name" => nullable_string(),
          "inserted_at" => date_time(),
          "updated_at" => date_time()
        }),
      "Ruleset" =>
        object(%{
          "id" => string(),
          "name" => string(),
          "description" => nullable_string(),
          "version" => integer(),
          "categories" => array(string()),
          "updated_by" => string(),
          "effective_count" => integer(),
          "pool_count" => integer(),
          "inserted_at" => date_time(),
          "updated_at" => date_time()
        }),
      "Repository" =>
        object(%{
          "id" => string(),
          "name" => string(),
          "url" => string(),
          "repo_type" => string(),
          "last_updated_at" => date_time(),
          "last_update_status" => nullable_string(),
          "last_update_error" => nullable_string(),
          "rule_count" => integer(),
          "inserted_at" => date_time(),
          "updated_at" => date_time()
        }),
      "AuditEntry" =>
        object(%{
          "id" => string(),
          "timestamp" => date_time(),
          "actor" => string(),
          "actor_type" => string(),
          "action" => string(),
          "target_type" => string(),
          "target_id" => string(),
          "result" => string(),
          "detail" => %{"type" => "object", "additionalProperties" => true}
        }),
      "User" =>
        object(%{
          "id" => string(),
          "username" => string(),
          "display_name" => string(),
          "role" => string(),
          "active" => boolean(),
          "must_change_password" => boolean(),
          "inserted_at" => date_time(),
          "updated_at" => date_time()
        }),
      "ApiToken" =>
        object(%{
          "id" => string(),
          "name" => string(),
          "user_id" => string(),
          "permissions" => array(string()),
          "expires_at" => date_time(),
          "revoked_at" => date_time(),
          "inserted_at" => date_time(),
          "updated_at" => date_time()
        }),
      "DataEnvelope" =>
        object(%{
          "data" => %{"type" => "object", "additionalProperties" => true}
        }),
      "PaginatedEnvelope" =>
        object(%{
          "data" => array(%{"type" => "object", "additionalProperties" => true}),
          "meta" => %{"$ref" => "#/components/schemas/PaginationMeta"}
        }),
      "ApiTokenCreateResponse" =>
        object(%{
          "data" => %{"$ref" => "#/components/schemas/ApiToken"},
          "token" => string()
        })
    }
  end

  def object(properties, required \\ []) do
    %{"type" => "object", "properties" => properties}
    |> maybe_required(required)
  end

  def array(item_schema), do: %{"type" => "array", "items" => item_schema}
  def string, do: %{"type" => "string"}
  def nullable_string, do: %{"type" => "string", "nullable" => true}
  def integer, do: %{"type" => "integer"}
  def boolean, do: %{"type" => "boolean"}
  def date_time, do: %{"type" => "string", "format" => "date-time", "nullable" => true}

  def data_envelope(schema) do
    object(%{"data" => schema})
  end

  def paginated_envelope(schema) do
    object(%{
      "data" => array(schema),
      "meta" => %{"$ref" => "#/components/schemas/PaginationMeta"}
    })
  end

  defp maybe_required(schema, []), do: schema
  defp maybe_required(schema, required), do: Map.put(schema, "required", required)
end
