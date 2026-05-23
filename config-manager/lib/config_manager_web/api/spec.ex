defmodule ConfigManagerWeb.Api.Spec do
  @moduledoc "OpenAPI 3.0 document for the implemented bearer-token Public API."

  alias ConfigManagerWeb.Api.{Errors, Pagination, Schemas}

  @operations [
    %{
      method: :post,
      path: "/api/v1/enrollments/{id}/approve",
      router_path: "/api/v1/enrollments/:id/approve",
      operation_id: "approveEnrollment",
      tag: "Enrollment",
      permission: "enrollment:manage",
      summary: "Approve an enrollment request",
      description:
        "Approves a pending sensor enrollment request and returns the enrollment bundle.",
      success_status: 200,
      response_schema: "DataEnvelope"
    },
    %{
      method: :post,
      path: "/api/v1/enrollments/{id}/deny",
      router_path: "/api/v1/enrollments/:id/deny",
      operation_id: "denyEnrollment",
      tag: "Enrollment",
      permission: "enrollment:manage",
      summary: "Deny an enrollment request",
      description: "Denies a pending sensor enrollment request.",
      success_status: 200,
      response_schema: "DataEnvelope"
    },
    %{
      method: :post,
      path: "/api/v1/pcap-config",
      router_path: "/api/v1/pcap-config",
      operation_id: "updatePcapConfig",
      tag: "PCAP",
      permission: "pcap:configure",
      summary: "Update sensor PCAP configuration",
      description: "Updates PCAP ring and alert window settings for a sensor.",
      success_status: 200,
      response_schema: "PcapConfig",
      request_example: %{
        "pod_id" => "sensor-01-id",
        "pcap_ring_size_mb" => 512,
        "pre_alert_window_sec" => 30,
        "post_alert_window_sec" => 60,
        "alert_severity_threshold" => 3
      }
    },
    %{
      method: :get,
      path: "/api/v1/pcap/requests",
      router_path: "/api/v1/pcap/requests",
      operation_id: "listPcapRequests",
      tag: "PCAP",
      permission: "pcap:search",
      summary: "List PCAP requests",
      description: "Returns paginated PCAP search and retrieval request history.",
      success_status: 200,
      response_schema: "PcapRequest",
      paginated: true,
      parameters: Pagination.parameters(25)
    },
    %{
      method: :get,
      path: "/api/v1/pcap/requests/{id}",
      router_path: "/api/v1/pcap/requests/:id",
      operation_id: "showPcapRequest",
      tag: "PCAP",
      permission: "pcap:search",
      summary: "Show a PCAP request",
      description: "Returns detail for one PCAP search or retrieval request.",
      success_status: 200,
      response_schema: "PcapRequest"
    },
    %{
      method: :get,
      path: "/api/v1/pcap/requests/{id}/manifest",
      router_path: "/api/v1/pcap/requests/:id/manifest",
      operation_id: "exportPcapManifest",
      tag: "PCAP",
      permission: "pcap:search",
      summary: "Export a PCAP custody manifest",
      description: "Returns the custody manifest for a PCAP request.",
      success_status: 200,
      response_schema: "PcapManifest",
      raw_response: true
    },
    %{
      method: :post,
      path: "/api/v1/pcap/carve",
      router_path: "/api/v1/pcap/carve",
      operation_id: "createPcapCarve",
      tag: "PCAP",
      permission: "pcap:search",
      summary: "Submit a PCAP search request",
      description:
        "Creates a PCAP search/retrieval request using Community ID, five-tuple, alert ID, or Zeek UID criteria.",
      success_status: 202,
      response_schema: "PcapRequest",
      request_example: %{
        "pod_id" => "sensor-01-id",
        "search_type" => "community_id",
        "community_id" => "1:example-community-id"
      }
    },
    %{
      method: :get,
      path: "/api/v1/pcap/requests/{id}/download",
      router_path: "/api/v1/pcap/requests/:id/download",
      operation_id: "downloadPcap",
      tag: "PCAP",
      permission: "pcap:download",
      summary: "Download a completed PCAP",
      description: "Downloads the completed PCAP artifact when the request is ready.",
      success_status: 200,
      binary_response: true
    },
    %{
      method: :post,
      path: "/api/v1/rules/deploy",
      router_path: "/api/v1/rules/deploy",
      operation_id: "deployRuleset",
      tag: "Rules",
      permission: "rules:deploy",
      summary: "Deploy the assigned ruleset to a pool",
      description: "Starts a ruleset deployment for the supplied pool.",
      success_status: 200,
      response_schema: "DataEnvelope",
      request_example: %{"pool_id" => "pool-id", "start_task" => true}
    },
    %{
      method: :get,
      path: "/api/v1/rules",
      router_path: "/api/v1/rules",
      operation_id: "listRules",
      tag: "Rules",
      permission: "sensors:view",
      summary: "List rules",
      description: "Returns paginated Suricata rule records.",
      success_status: 200,
      response_schema: "Rule",
      paginated: true,
      parameters: Pagination.parameters(25)
    },
    %{
      method: :get,
      path: "/api/v1/rulesets",
      router_path: "/api/v1/rulesets",
      operation_id: "listRulesets",
      tag: "Rules",
      permission: "sensors:view",
      summary: "List rulesets",
      description: "Returns ruleset summaries.",
      success_status: 200,
      response_schema: "Ruleset",
      array_response: true
    },
    %{
      method: :get,
      path: "/api/v1/repositories",
      router_path: "/api/v1/repositories",
      operation_id: "listRepositories",
      tag: "Rules",
      permission: "sensors:view",
      summary: "List rule repositories",
      description: "Returns configured rule repositories.",
      success_status: 200,
      response_schema: "Repository",
      array_response: true
    },
    %{
      method: :post,
      path: "/api/v1/rules",
      router_path: "/api/v1/rules",
      operation_id: "createRule",
      tag: "Rules",
      permission: "rules:manage",
      summary: "Create a manual rule",
      description: "Creates a managed Suricata rule.",
      success_status: 201,
      response_schema: "Rule",
      request_example: %{"sid" => 2_400_001, "message" => "Example managed rule", "severity" => 3}
    },
    %{
      method: :post,
      path: "/api/v1/rulesets",
      router_path: "/api/v1/rulesets",
      operation_id: "createRuleset",
      tag: "Rules",
      permission: "rules:manage",
      summary: "Create a ruleset",
      description: "Creates a ruleset from selected categories and rules.",
      success_status: 201,
      response_schema: "Ruleset",
      request_example: %{"name" => "Managed Ruleset", "description" => "Example ruleset"}
    },
    %{
      method: :post,
      path: "/api/v1/repositories",
      router_path: "/api/v1/repositories",
      operation_id: "createRepository",
      tag: "Rules",
      permission: "rules:manage",
      summary: "Create a rule repository",
      description: "Creates a rule repository record.",
      success_status: 201,
      response_schema: "Repository",
      request_example: %{
        "name" => "Example repository",
        "url" => "file:///opt/ravenwire/rules",
        "repo_type" => "local"
      }
    },
    %{
      method: :get,
      path: "/api/v1/deployments",
      router_path: "/api/v1/deployments",
      operation_id: "listDeployments",
      tag: "Deployments",
      permission: "sensors:view",
      summary: "List deployments",
      description: "Returns paginated deployment records.",
      success_status: 200,
      response_schema: "Deployment",
      paginated: true,
      parameters: Pagination.parameters(25)
    },
    %{
      method: :get,
      path: "/api/v1/deployments/{id}",
      router_path: "/api/v1/deployments/:id",
      operation_id: "showDeployment",
      tag: "Deployments",
      permission: "sensors:view",
      summary: "Show a deployment",
      description: "Returns deployment detail.",
      success_status: 200,
      response_schema: "Deployment"
    },
    %{
      method: :post,
      path: "/api/v1/deployments",
      router_path: "/api/v1/deployments",
      operation_id: "createDeployment",
      tag: "Deployments",
      permission: "deployments:manage",
      summary: "Create a deployment",
      description: "Creates a desired-state deployment for a pool.",
      success_status: 201,
      response_schema: "Deployment",
      request_example: %{"pool_id" => "pool-id", "start_orchestrator" => true}
    },
    %{
      method: :post,
      path: "/api/v1/deployments/{id}/cancel",
      router_path: "/api/v1/deployments/:id/cancel",
      operation_id: "cancelDeployment",
      tag: "Deployments",
      permission: "deployments:manage",
      summary: "Cancel a deployment",
      description: "Cancels a pending or active deployment.",
      success_status: 200,
      response_schema: "Deployment"
    },
    %{
      method: :post,
      path: "/api/v1/deployments/{id}/rollback",
      router_path: "/api/v1/deployments/:id/rollback",
      operation_id: "rollbackDeployment",
      tag: "Deployments",
      permission: "deployments:manage",
      summary: "Rollback a deployment",
      description: "Creates a rollback deployment from a previous deployment.",
      success_status: 200,
      response_schema: "Deployment"
    },
    %{
      method: :post,
      path: "/api/v1/support-bundles",
      router_path: "/api/v1/support-bundles",
      operation_id: "requestSupportBundle",
      tag: "Operations",
      permission: "bundle:download",
      summary: "Request a support bundle",
      description: "Requests a support bundle from a sensor.",
      success_status: 200,
      response_schema: "DataEnvelope",
      request_example: %{"pod_id" => "sensor-01-id"}
    },
    %{
      method: :get,
      path: "/api/v1/audit",
      router_path: "/api/v1/audit",
      operation_id: "listAudit",
      tag: "Audit",
      permission: "audit:view",
      summary: "List audit entries",
      description: "Returns audit entries with optional filters.",
      success_status: 200,
      response_schema: "AuditEntry",
      paginated: true,
      parameters: Pagination.parameters(50)
    },
    %{
      method: :get,
      path: "/api/v1/audit/export",
      router_path: "/api/v1/audit/export",
      operation_id: "exportAudit",
      tag: "Audit",
      permission: "audit:export",
      summary: "Export audit entries",
      description: "Exports audit entries as JSON or CSV.",
      success_status: 200,
      raw_response: true,
      parameters: [
        %{
          "name" => "format",
          "in" => "query",
          "required" => false,
          "schema" => %{"type" => "string", "enum" => ["json", "csv"], "default" => "json"}
        }
      ]
    },
    %{
      method: :post,
      path: "/api/v1/admin/users",
      router_path: "/api/v1/admin/users",
      operation_id: "createUser",
      tag: "Admin",
      permission: "users:manage",
      summary: "Create a user",
      description: "Creates a Config Manager user.",
      success_status: 201,
      response_schema: "User",
      request_example: %{
        "username" => "automation-user",
        "display_name" => "Automation User",
        "role" => "viewer",
        "password" => "change-me-long-enough"
      }
    },
    %{
      method: :post,
      path: "/api/v1/admin/api-tokens",
      router_path: "/api/v1/admin/api-tokens",
      operation_id: "createApiToken",
      tag: "Admin",
      permission: "tokens:manage",
      summary: "Create an API token",
      description: "Creates a bearer API token and returns the raw token once.",
      success_status: 201,
      response_schema: "ApiTokenCreateResponse",
      raw_response: true,
      request_example: %{"name" => "automation-token", "permissions" => ["sensors:view"]}
    }
  ]

  def spec do
    %{
      "openapi" => "3.0.3",
      "info" => %{
        "title" => "RavenWire Config Manager Public API",
        "version" => app_version(),
        "description" =>
          "Bearer-token API for implemented RavenWire Config Manager operator workflows. Internal Sensor Agent bootstrap and mTLS control routes are intentionally omitted.",
        "contact" => %{"name" => "RavenWire Operators"}
      },
      "servers" => [
        %{"url" => "/", "description" => "Current Config Manager origin"}
      ],
      "tags" => tags(),
      "paths" => paths(),
      "components" => %{
        "securitySchemes" => %{
          "bearerAuth" => %{
            "type" => "http",
            "scheme" => "bearer",
            "bearerFormat" => "RavenWire API token"
          }
        },
        "schemas" => Schemas.components()
      }
    }
  end

  def operations, do: @operations

  def operation_for(method, request_path) do
    method = method |> to_string() |> String.downcase() |> String.to_atom()

    Enum.find(@operations, fn operation ->
      operation.method == method and path_matches?(operation.router_path, request_path)
    end)
  end

  defp paths do
    @operations
    |> Enum.group_by(& &1.path)
    |> Enum.map(fn {path, operations} ->
      {path,
       operations
       |> Enum.map(fn operation ->
         {operation.method |> Atom.to_string(), operation(operation)}
       end)
       |> Map.new()}
    end)
    |> Map.new()
  end

  defp operation(operation) do
    %{
      "operationId" => operation.operation_id,
      "tags" => [operation.tag],
      "summary" => operation.summary,
      "description" => operation.description,
      "security" => [%{"bearerAuth" => []}],
      "x-ravenwire-permission" => operation.permission,
      "parameters" => path_parameters(operation.path) ++ Map.get(operation, :parameters, []),
      "responses" => responses(operation)
    }
    |> maybe_request_body(operation)
  end

  defp responses(operation) do
    success_code = operation.success_status |> Integer.to_string()

    Map.merge(
      %{
        success_code => %{
          "description" => "Successful response",
          "content" => success_content(operation)
        }
      },
      Errors.standard_responses()
    )
  end

  defp success_content(%{binary_response: true}) do
    %{"application/octet-stream" => %{"schema" => %{"type" => "string", "format" => "binary"}}}
  end

  defp success_content(%{raw_response: true, response_schema: schema}) do
    %{"application/json" => %{"schema" => ref(schema)}}
  end

  defp success_content(%{raw_response: true}) do
    %{
      "application/json" => %{"schema" => %{"type" => "object", "additionalProperties" => true}},
      "text/csv" => %{"schema" => %{"type" => "string"}}
    }
  end

  defp success_content(%{paginated: true, response_schema: schema}) do
    %{"application/json" => %{"schema" => Schemas.paginated_envelope(ref(schema))}}
  end

  defp success_content(%{array_response: true, response_schema: schema}) do
    %{"application/json" => %{"schema" => Schemas.data_envelope(Schemas.array(ref(schema)))}}
  end

  defp success_content(%{response_schema: "DataEnvelope"}) do
    %{"application/json" => %{"schema" => ref("DataEnvelope")}}
  end

  defp success_content(%{response_schema: schema}) do
    %{"application/json" => %{"schema" => Schemas.data_envelope(ref(schema))}}
  end

  defp maybe_request_body(spec, %{method: :post} = operation) do
    Map.put(spec, "requestBody", %{
      "required" => true,
      "content" => %{
        "application/json" => %{
          "schema" => %{"type" => "object", "additionalProperties" => true},
          "example" => Map.get(operation, :request_example, %{})
        }
      }
    })
  end

  defp maybe_request_body(spec, _operation), do: spec

  defp path_parameters(path) do
    ~r/\{([^}]+)\}/
    |> Regex.scan(path)
    |> Enum.map(fn [_match, name] ->
      %{
        "name" => name,
        "in" => "path",
        "required" => true,
        "schema" => %{"type" => "string"}
      }
    end)
  end

  defp tags do
    @operations
    |> Enum.map(& &1.tag)
    |> Enum.uniq()
    |> Enum.map(&%{"name" => &1})
  end

  defp ref(schema), do: %{"$ref" => "#/components/schemas/#{schema}"}

  defp path_matches?(router_path, request_path) do
    router_path
    |> String.split("/", trim: true)
    |> segments_match?(String.split(request_path, "/", trim: true))
  end

  defp segments_match?([], []), do: true

  defp segments_match?(["*" <> _name], _request_segments), do: true

  defp segments_match?([":" <> _name | router_segments], [_request_segment | request_segments]) do
    segments_match?(router_segments, request_segments)
  end

  defp segments_match?([segment | router_segments], [segment | request_segments]) do
    segments_match?(router_segments, request_segments)
  end

  defp segments_match?(_router_segments, _request_segments), do: false

  defp app_version do
    :config_manager
    |> Application.spec(:vsn)
    |> to_string()
  end
end
