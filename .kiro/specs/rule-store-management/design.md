# Design Document: Rule Store Management

## Overview

This design adds a full Suricata Rule Store to the RavenWire Config Manager: database-backed rule storage indexed by SID, category-based organization, external repository management with on-demand fetching and parsing, named ruleset composition with category and SID-level granularity, ruleset-to-pool assignment, managed rule deployment through the existing `SensorAgentClient.push_rule_bundle/3` path, deployed version tracking per pool and per sensor, and out-of-sync sensor detection. The existing paste-and-deploy page at `/rules` is preserved as a "Quick Deploy" action.

The implementation introduces four new database tables (`suricata_rules`, `rule_repositories`, `rulesets`, `ruleset_rules`) and two join/tracking tables (`pool_ruleset_assignments`, plus a `last_deployed_rule_version` field on `sensor_pods`). A new `ConfigManager.Rules` context module provides the public API for all rule store operations. Rule repository fetching and archive parsing run as supervised async tasks. Ruleset compilation produces the `%{filename => content}` map expected by the existing `RuleDeployer` and `SensorAgentClient`.

### Key Design Decisions

1. **Dedicated `ConfigManager.Rules` context module**: All rule CRUD, repository management, ruleset composition, assignment, and deployment logic lives in a single context module. LiveView modules call through this context. This follows the project pattern established by `ConfigManager.Enrollment` and `ConfigManager.Pools`.

2. **`Ecto.Multi` for transactional audit writes**: Every rule store mutation uses `Ecto.Multi` with `Audit.append_multi/2` so the audit entry and data change succeed or fail atomically, consistent with all other Config Manager specs.

3. **SID-based upsert for repository imports**: Rules are uniquely identified by SID. Repository updates upsert by SID — updating rule text and metadata when the imported revision is >= the stored revision, inserting new SIDs, and preserving per-rule enabled/disabled state for existing SIDs. This prevents duplicate rules and preserves operator customizations.

4. **Category derived from filename**: Rule categories are derived from the `.rules` filename in the repository archive (e.g., `emerging-malware.rules` → category `emerging-malware`). This matches the standard ET Open and Snort Community distribution format.

5. **Ruleset composition model**: A Ruleset defines its membership through included categories and explicit SID overrides (includes and excludes). The effective rule set is computed at deployment time: all enabled rules in included categories, plus explicit SID includes, minus explicit SID excludes. This avoids materializing a large join table and keeps rulesets lightweight.

6. **One ruleset per pool**: Each pool can have at most one assigned ruleset. This simplifies the deployment model — operators know exactly which detection content a pool runs.

7. **Async repository fetch under Task.Supervisor**: Repository updates (HTTP fetch, archive extraction, rule parsing, bulk upsert) run under `ConfigManager.Rules.TaskSupervisor` to avoid blocking the LiveView process. Progress is broadcast via PubSub.

8. **Reuse existing deployment infrastructure**: Rule deployment compiles the ruleset into the `%{filename => content}` map format already consumed by `SensorAgentClient.push_rule_bundle/3`. No changes to the Sensor Agent API are needed.

9. **PropCheck for property-based testing**: The project already includes `propcheck ~> 1.4`. Property tests validate rule parsing round-trips, ruleset composition correctness, SID upsert idempotence, and deployment file compilation.

## Architecture

### System Context

```mermaid
graph TB
    subgraph "Config Manager (Phoenix)"
        Router --> AuthPipeline[Auth Pipeline]
        AuthPipeline --> RuleStoreLive[RuleStoreLive<br/>/rules/store]
        AuthPipeline --> CategoriesLive[CategoriesLive<br/>/rules/categories]
        AuthPipeline --> RepositoriesLive[RepositoriesLive<br/>/rules/repositories]
        AuthPipeline --> RulesetsLive[RulesetsLive<br/>/rules/rulesets]
        AuthPipeline --> RulesetDetailLive[RulesetDetailLive<br/>/rules/rulesets/:id]
        AuthPipeline --> RuleDeploymentsLive[RuleDeploymentsLive<br/>/rules/deployments]
        AuthPipeline --> QuickDeployLive[RuleDeploymentLive<br/>/rules (existing)]
    end

    subgraph "Context Layer"
        RuleStoreLive --> Rules[ConfigManager.Rules]
        CategoriesLive --> Rules
        RepositoriesLive --> Rules
        RulesetsLive --> Rules
        RulesetDetailLive --> Rules
        RuleDeploymentsLive --> Rules
        Rules --> Parser[Rules.Parser]
        Rules --> Fetcher[Rules.Fetcher]
        Rules --> Compiler[Rules.Compiler]
        Rules --> Repo[(Ecto / SQLite)]
        Rules --> Audit[ConfigManager.Audit]
        Rules --> PubSub[Phoenix PubSub]
    end

    subgraph "Async Tasks"
        Fetcher --> TaskSupervisor[Task.Supervisor]
        TaskSupervisor --> HTTP[HTTP Client / Finch]
        HTTP --> ExternalRepos[ET Open / Snort / Custom URLs]
    end

    subgraph "Deployment Path"
        Rules --> RuleDeployer[RuleDeployer]
        RuleDeployer --> SensorAgentClient[SensorAgentClient]
        SensorAgentClient --> Sensors[Sensor Agents]
    end

    subgraph "Auth Subsystem"
        AuthPipeline --> Policy[Policy Module]
    end

    Browser[Operator Browser] --> Router
```

### Request Flow

**Rule Store browse/search:**
1. Browser navigates to `/rules/store`
2. Auth pipeline validates session, checks `sensors:view` permission
3. `RuleStoreLive.mount/3` calls `Rules.list_rules/1` with default sort and pagination
4. Subscribes to `"rules"` PubSub topic for real-time updates after imports
5. Renders paginated, searchable rule table

**Repository update:**
1. User clicks "Update Now" on `/rules/repositories` (requires `rules:manage`)
2. `handle_event("update_repo", %{"id" => id}, socket)` calls `Rules.update_repository/2`
3. Context sets repository status to `updating`, writes audit entry, broadcasts status
4. Spawns async task under `Rules.TaskSupervisor`:
   a. `Fetcher.fetch/1` downloads archive via HTTP/HTTPS
   b. `Fetcher.extract/1` extracts `.rules` files from `.tar.gz`
   c. `Parser.parse_files/1` parses each rule file, extracts SID/msg/rev/classtype per rule
   d. `Rules.bulk_upsert_rules/3` upserts rules by SID within a transaction
5. On completion: updates repository status and timestamp, broadcasts `{:repository_updated, repo_id}`
6. On failure: updates repository status with error, broadcasts failure

**Ruleset creation:**
1. User navigates to `/rules/rulesets/new` (requires `rules:manage`)
2. Fills form: name, description, selects categories, adds SID overrides
3. `handle_event("save", params, socket)` calls `Rules.create_ruleset/2`
4. Context validates name uniqueness, creates ruleset with version 1, writes audit entry
5. Redirects to `/rules/rulesets/:id`

**Ruleset deployment to pool:**
1. User clicks "Deploy Rules" on pool detail or ruleset detail (requires `rules:deploy`)
2. `Rules.deploy_ruleset_to_pool/3` compiles the ruleset via `Compiler.compile/1`
3. Compiler produces `%{filename => content}` map (one file per category + overrides file)
4. Calls `RuleDeployer.deploy_to_pool/3` with the compiled rule map
5. On per-sensor success: updates `last_deployed_rule_version` on sensor
6. Records audit entry with deployment results

### Module Layout

```
lib/config_manager/
├── rules.ex                               # Rules context (public API)
├── rules/
│   ├── suricata_rule.ex                   # Ecto schema
│   ├── rule_repository.ex                 # Ecto schema
│   ├── ruleset.ex                         # Ecto schema
│   ├── ruleset_rule.ex                    # Ecto schema (SID overrides)
│   ├── pool_ruleset_assignment.ex         # Ecto schema
│   ├── parser.ex                          # Suricata rule text parser
│   ├── fetcher.ex                         # HTTP fetch + archive extraction
│   └── compiler.ex                        # Ruleset → rule file map compilation

lib/config_manager_web/
├── live/
│   ├── rules_live/
│   │   ├── store_live.ex                  # /rules/store — browse/search rules
│   │   ├── categories_live.ex             # /rules/categories — category management
│   │   ├── repositories_live.ex           # /rules/repositories — repo management
│   │   ├── rulesets_live.ex               # /rules/rulesets — ruleset list
│   │   ├── ruleset_detail_live.ex         # /rules/rulesets/:id — detail + edit
│   │   └── deployments_live.ex            # /rules/deployments — deployment history
│   └── rule_deployment_live.ex            # /rules — existing quick deploy (updated)
├── router.ex                              # Extended with /rules/* routes

priv/repo/migrations/
├── YYYYMMDDHHMMSS_create_rule_store_tables.exs
```


## Components and Interfaces

### 1. `ConfigManager.Rules` — Rules Context Module

The primary public API for all rule store operations.

```elixir
defmodule ConfigManager.Rules do
  @moduledoc "Rule Store management context — rules, repositories, rulesets, deployment."

  alias ConfigManager.{Repo, Audit}
  alias ConfigManager.Rules.{SuricataRule, RuleRepository, Ruleset, RulesetRule, PoolRulesetAssignment, Parser, Fetcher, Compiler}
  alias Ecto.Multi
  import Ecto.Query

  # ── Rule CRUD ──────────────────────────────────────────────────────────────

  @doc "Lists rules with search, filtering, sorting, and pagination."
  def list_rules(opts \\ [])
      :: %{entries: [SuricataRule.t()], page: integer(), total_pages: integer(), total_count: integer()}

  @doc "Gets a single rule by ID."
  def get_rule(id) :: SuricataRule.t() | nil

  @doc "Gets a single rule by SID."
  def get_rule_by_sid(sid) :: SuricataRule.t() | nil

  @doc "Toggles a rule's enabled status. Records audit entry."
  def toggle_rule(rule, actor)
      :: {:ok, SuricataRule.t()} | {:error, Ecto.Changeset.t()}

  @doc "Bulk toggles enabled status for a list of rule IDs. Records summary audit entry."
  def bulk_toggle_rules(rule_ids, enabled, actor)
      :: {:ok, integer()} | {:error, term()}

  # ── Category Operations ────────────────────────────────────────────────────

  @doc "Lists all categories with rule counts and enabled/disabled counts."
  def list_categories()
      :: [%{name: String.t(), total: integer(), enabled: integer(), disabled: integer()}]

  @doc "Toggles all rules in a category. Records audit entry."
  def toggle_category(category_name, enabled, actor)
      :: {:ok, integer()} | {:error, term()}

  # ── Repository Management ──────────────────────────────────────────────────

  @doc "Lists all repositories."
  def list_repositories() :: [RuleRepository.t()]

  @doc "Gets a repository by ID."
  def get_repository(id) :: RuleRepository.t() | nil

  @doc "Creates a new repository. Records audit entry."
  def create_repository(attrs, actor)
      :: {:ok, RuleRepository.t()} | {:error, Ecto.Changeset.t()}

  @doc "Deletes a repository (preserves imported rules). Records audit entry."
  def delete_repository(repo, actor)
      :: {:ok, RuleRepository.t()} | {:error, term()}

  @doc """
  Triggers an async repository update. Sets status to 'updating',
  spawns fetch/parse/upsert task under TaskSupervisor.
  Returns immediately with {:ok, :updating}.
  """
  def update_repository(repo, actor)
      :: {:ok, :updating} | {:error, term()}

  @doc """
  Bulk upserts rules from parsed repository data.
  Upserts by SID: updates if imported rev >= stored rev, inserts new SIDs.
  Preserves existing enabled/disabled state.
  Called by the async fetcher task.
  """
  def bulk_upsert_rules(rules_data, repository_id, actor)
      :: {:ok, %{added: integer(), updated: integer(), unchanged: integer()}} | {:error, term()}

  # ── Ruleset Management ─────────────────────────────────────────────────────

  @doc "Lists all rulesets with effective rule counts and assigned pool counts."
  def list_rulesets()
      :: [%{ruleset: Ruleset.t(), effective_count: integer(), pool_count: integer()}]

  @doc "Gets a ruleset by ID with preloaded overrides."
  def get_ruleset(id) :: Ruleset.t() | nil

  @doc "Gets a ruleset by ID. Raises if not found."
  def get_ruleset!(id) :: Ruleset.t()

  @doc "Creates a new ruleset. Records audit entry."
  def create_ruleset(attrs, actor)
      :: {:ok, Ruleset.t()} | {:error, Ecto.Changeset.t()}

  @doc "Updates a ruleset's categories or SID overrides. Increments version. Records audit entry."
  def update_ruleset(ruleset, attrs, actor)
      :: {:ok, Ruleset.t()} | {:error, Ecto.Changeset.t()}

  @doc "Deletes a ruleset and its pool assignments. Records audit entry."
  def delete_ruleset(ruleset, actor)
      :: {:ok, Ruleset.t()} | {:error, term()}

  @doc "Computes the effective rule set for a ruleset (all enabled rules matching composition)."
  def effective_rules(ruleset_id)
      :: [SuricataRule.t()]

  @doc "Returns the count of effective rules for a ruleset."
  def effective_rule_count(ruleset_id) :: integer()

  # ── Pool Assignment ────────────────────────────────────────────────────────

  @doc "Assigns a ruleset to a pool (replaces existing assignment). Records audit entry."
  def assign_ruleset_to_pool(ruleset, pool, actor)
      :: {:ok, PoolRulesetAssignment.t()} | {:error, term()}

  @doc "Removes the ruleset assignment from a pool. Records audit entry."
  def unassign_ruleset_from_pool(pool, actor)
      :: {:ok, PoolRulesetAssignment.t()} | {:error, :no_assignment}

  @doc "Gets the current ruleset assignment for a pool."
  def pool_assignment(pool_id) :: PoolRulesetAssignment.t() | nil

  @doc "Gets the assigned ruleset for a pool."
  def pool_ruleset(pool_id) :: Ruleset.t() | nil

  # ── Deployment ─────────────────────────────────────────────────────────────

  @doc """
  Deploys the pool's assigned ruleset to all enrolled sensors in the pool.
  Compiles the ruleset into rule files, calls RuleDeployer.deploy_to_pool/3,
  updates per-sensor last_deployed_rule_version on success.
  Records audit entry with per-sensor results.
  """
  def deploy_ruleset_to_pool(pool_id, actor, opts \\ [])
      :: {:ok, %{results: [map()], version: integer()}} | {:error, term()}

  @doc "Returns the deployed rule version for a pool (from the most recent successful deployment)."
  def deployed_rule_version(pool_id) :: integer() | nil

  @doc "Lists rule deployment history with pagination."
  def list_rule_deployments(opts \\ [])
      :: %{entries: [map()], page: integer(), total_pages: integer()}

  @doc "Lists rule deployment history for a specific pool."
  def list_pool_rule_deployments(pool_id, opts \\ [])
      :: %{entries: [map()], page: integer(), total_pages: integer()}

  # ── Drift Detection ────────────────────────────────────────────────────────

  @doc "Returns out-of-sync sensor count for a pool."
  def out_of_sync_count(pool_id) :: integer()

  @doc "Returns per-sensor sync status for a pool."
  def sensor_sync_statuses(pool_id)
      :: [%{sensor: SensorPod.t(), deployed_version: integer() | nil, expected_version: integer() | nil, in_sync: boolean()}]
end
```

### 2. `ConfigManager.Rules.SuricataRule` — Ecto Schema

```elixir
defmodule ConfigManager.Rules.SuricataRule do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "suricata_rules" do
    field :sid, :integer
    field :message, :string
    field :raw_text, :string
    field :category, :string
    field :classtype, :string
    field :severity, :integer, default: 2
    field :revision, :integer, default: 1
    field :enabled, :boolean, default: true
    field :repository_id, :binary_id
    field :repository_name, :string

    timestamps()
  end

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [:sid, :message, :raw_text, :category, :classtype, :severity, :revision, :enabled, :repository_id, :repository_name])
    |> validate_required([:sid, :raw_text, :category])
    |> validate_number(:sid, greater_than: 0)
    |> validate_number(:revision, greater_than_or_equal_to: 0)
    |> validate_inclusion(:severity, [1, 2, 3])
    |> unique_constraint(:sid)
  end

  def toggle_changeset(rule, enabled) do
    change(rule, enabled: enabled)
  end
end
```

### 3. `ConfigManager.Rules.RuleRepository` — Ecto Schema

```elixir
defmodule ConfigManager.Rules.RuleRepository do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  @valid_types ~w(et_open snort_community custom)

  schema "rule_repositories" do
    field :name, :string
    field :url, :string
    field :repo_type, :string, default: "custom"
    field :last_updated_at, :utc_datetime
    field :last_update_status, :string, default: "never_updated"
    field :last_update_error, :string
    field :rule_count, :integer, default: 0

    timestamps()
  end

  def changeset(repo, attrs) do
    repo
    |> cast(attrs, [:name, :url, :repo_type])
    |> validate_required([:name, :url])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:url, ~r/^https?:\/\/.+/, message: "must be a valid HTTP or HTTPS URL")
    |> validate_inclusion(:repo_type, @valid_types)
    |> unique_constraint(:name, name: :rule_repositories_name_nocase_index)
  end

  def update_status_changeset(repo, attrs) do
    repo
    |> cast(attrs, [:last_updated_at, :last_update_status, :last_update_error, :rule_count])
  end
end
```

### 4. `ConfigManager.Rules.Ruleset` — Ecto Schema

```elixir
defmodule ConfigManager.Rules.Ruleset do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "rulesets" do
    field :name, :string
    field :description, :string
    field :version, :integer, default: 1
    field :categories, {:array, :string}, default: []
    field :updated_by, :string

    has_many :overrides, ConfigManager.Rules.RulesetRule
    has_many :pool_assignments, ConfigManager.Rules.PoolRulesetAssignment

    timestamps()
  end

  @name_format ~r/^[a-zA-Z0-9._-]+$/

  def create_changeset(ruleset, attrs, actor) do
    ruleset
    |> cast(attrs, [:name, :description, :categories])
    |> normalize_name()
    |> validate_required([:name])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:name, @name_format,
         message: "must contain only alphanumeric characters, hyphens, underscores, and periods")
    |> unique_constraint(:name, name: :rulesets_name_nocase_index)
    |> put_change(:version, 1)
    |> put_change(:updated_by, actor)
  end

  def update_changeset(ruleset, attrs, actor) do
    ruleset
    |> cast(attrs, [:name, :description, :categories])
    |> normalize_name()
    |> validate_required([:name])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:name, @name_format,
         message: "must contain only alphanumeric characters, hyphens, underscores, and periods")
    |> unique_constraint(:name, name: :rulesets_name_nocase_index)
    |> maybe_increment_version(actor)
  end

  defp normalize_name(changeset) do
    case get_change(changeset, :name) do
      nil -> changeset
      name -> put_change(changeset, :name, String.trim(name))
    end
  end

  defp maybe_increment_version(changeset, actor) do
    content_fields = [:categories]
    if Enum.any?(content_fields, &Map.has_key?(changeset.changes, &1)) do
      current = get_field(changeset, :version) || 1
      changeset
      |> put_change(:version, current + 1)
      |> put_change(:updated_by, actor)
    else
      changeset
    end
  end
end
```

### 5. `ConfigManager.Rules.RulesetRule` — SID Override Schema

```elixir
defmodule ConfigManager.Rules.RulesetRule do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_actions ~w(include exclude)

  schema "ruleset_rules" do
    field :ruleset_id, :binary_id
    field :sid, :integer
    field :action, :string  # "include" or "exclude"

    belongs_to :ruleset, ConfigManager.Rules.Ruleset, define_field: false

    timestamps()
  end

  def changeset(override, attrs) do
    override
    |> cast(attrs, [:ruleset_id, :sid, :action])
    |> validate_required([:ruleset_id, :sid, :action])
    |> validate_number(:sid, greater_than: 0)
    |> validate_inclusion(:action, @valid_actions)
    |> unique_constraint([:ruleset_id, :sid])
  end
end
```

### 6. `ConfigManager.Rules.PoolRulesetAssignment` — Ecto Schema

```elixir
defmodule ConfigManager.Rules.PoolRulesetAssignment do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "pool_ruleset_assignments" do
    field :pool_id, :binary_id
    field :ruleset_id, :binary_id
    field :assigned_by, :string
    field :deployed_rule_version, :integer

    belongs_to :pool, ConfigManager.SensorPool, define_field: false
    belongs_to :ruleset, ConfigManager.Rules.Ruleset, define_field: false

    timestamps()
  end

  def changeset(assignment, attrs) do
    assignment
    |> cast(attrs, [:pool_id, :ruleset_id, :assigned_by, :deployed_rule_version])
    |> validate_required([:pool_id, :ruleset_id, :assigned_by])
    |> unique_constraint(:pool_id, name: :pool_ruleset_assignments_pool_id_index)
    |> foreign_key_constraint(:pool_id)
    |> foreign_key_constraint(:ruleset_id)
  end
end
```

### 7. `ConfigManager.Rules.Parser` — Suricata Rule Parser

```elixir
defmodule ConfigManager.Rules.Parser do
  @moduledoc """
  Parses Suricata rule text files into structured rule data.
  Extracts SID, message, revision, classtype, and severity from rule text.
  """

  @doc """
  Parses a list of {filename, content} tuples into rule data maps.
  Category is derived from filename (e.g., "emerging-malware.rules" → "emerging-malware").
  Skips unparseable lines with warnings.
  Returns {:ok, [rule_data]} or {:error, reason}.
  """
  def parse_files(file_list)
      :: {:ok, [map()]} | {:error, term()}

  @doc """
  Parses a single rule line into a rule data map.
  Returns {:ok, map} or {:error, reason}.
  """
  def parse_rule(line)
      :: {:ok, map()} | {:error, String.t()}

  @doc """
  Extracts the SID from a rule line.
  Returns {:ok, integer} or {:error, reason}.
  """
  def extract_sid(line) :: {:ok, integer()} | {:error, String.t()}

  @doc """
  Extracts the msg keyword value from a rule line.
  """
  def extract_message(line) :: String.t() | nil

  @doc """
  Extracts the rev keyword value from a rule line.
  """
  def extract_revision(line) :: integer()

  @doc """
  Extracts the classtype keyword value from a rule line.
  """
  def extract_classtype(line) :: String.t() | nil

  @doc """
  Derives category name from a .rules filename.
  Strips the .rules extension and any path prefix.
  """
  def category_from_filename(filename) :: String.t()

  @doc """
  Formats a rule data map back into a valid Suricata rule line.
  Used for round-trip testing.
  """
  def format_rule(rule_data) :: String.t()
end
```

### 8. `ConfigManager.Rules.Fetcher` — Repository Fetch and Extract

```elixir
defmodule ConfigManager.Rules.Fetcher do
  @moduledoc """
  Fetches rule archives from external repositories and extracts .rules files.
  Runs as an async task under Rules.TaskSupervisor.
  """

  require Logger

  @fetch_timeout_ms 60_000

  @doc """
  Fetches a rule archive from the given URL.
  Returns {:ok, binary_data} or {:error, reason}.
  """
  def fetch(url) :: {:ok, binary()} | {:error, term()}

  @doc """
  Extracts .rules files from a .tar.gz archive.
  Returns {:ok, [{filename, content}]} or {:error, reason}.
  """
  def extract(archive_data) :: {:ok, [{String.t(), String.t()}]} | {:error, term()}

  @doc """
  Full pipeline: fetch archive, extract files, parse rules.
  Returns {:ok, [rule_data]} or {:error, reason}.
  """
  def fetch_and_parse(url) :: {:ok, [map()]} | {:error, term()}
end
```

### 9. `ConfigManager.Rules.Compiler` — Ruleset Compilation

```elixir
defmodule ConfigManager.Rules.Compiler do
  @moduledoc """
  Compiles a Ruleset into the %{filename => content} map format
  expected by SensorAgentClient.push_rule_bundle/3.
  """

  @doc """
  Compiles a ruleset into rule files.
  Produces one .rules file per included category containing enabled rules,
  plus a `local-overrides.rules` file for explicit SID includes.
  Excluded SIDs are omitted from their category files.

  Returns {:ok, %{filename => content}} or {:error, reason}.
  """
  def compile(ruleset_id) :: {:ok, map()} | {:error, term()}

  @doc """
  Returns the effective rule list for a ruleset without compiling to files.
  Used for UI display of effective rule count.
  """
  def effective_rules(ruleset_id) :: [SuricataRule.t()]

  @doc """
  Returns the effective rule count for a ruleset.
  """
  def effective_rule_count(ruleset_id) :: integer()
end
```


### 10. LiveView Modules

#### `RulesLive.StoreLive` — Rule Store Page (`/rules/store`)

```elixir
defmodule ConfigManagerWeb.RulesLive.StoreLive do
  use ConfigManagerWeb, :live_view

  # Mount: load paginated rules, subscribe to "rules" topic
  # Assigns: rules, page, total_pages, search_query, category_filter,
  #          repo_filter, sort_field, sort_dir, categories, repositories, current_user
  # Events:
  #   "search" — filter rules by query
  #   "filter" — apply category/repo filters
  #   "sort" — change sort column
  #   "page" — pagination
  #   "toggle_rule" — enable/disable single rule (rules:manage)
  #   "bulk_toggle" — enable/disable selected rules (rules:manage)
  #   "select_rule" / "select_all" — checkbox selection for bulk ops
  # PubSub: {:rules_updated, _} — refresh after repository import
  # RBAC: sensors:view for page; rules:manage for toggle actions
end
```

#### `RulesLive.CategoriesLive` — Categories Page (`/rules/categories`)

```elixir
defmodule ConfigManagerWeb.RulesLive.CategoriesLive do
  use ConfigManagerWeb, :live_view

  # Mount: load categories with counts
  # Assigns: categories, current_user
  # Events:
  #   "toggle_category" — enable/disable all rules in category (rules:manage)
  # RBAC: sensors:view for page; rules:manage for toggle
end
```

#### `RulesLive.RepositoriesLive` — Repositories Page (`/rules/repositories`)

```elixir
defmodule ConfigManagerWeb.RulesLive.RepositoriesLive do
  use ConfigManagerWeb, :live_view

  # Mount: load repositories, subscribe to "rule_repositories" topic
  # Assigns: repositories, show_add_form, changeset, current_user
  # Events:
  #   "add_repo" — show add form (rules:manage)
  #   "save_repo" — create repository (rules:manage)
  #   "update_repo" — trigger async update (rules:manage)
  #   "delete_repo" — delete repository with confirmation (rules:manage)
  # PubSub:
  #   {:repository_updating, repo_id} — show spinner
  #   {:repository_updated, repo_id} — refresh row
  #   {:repository_update_failed, repo_id, error} — show error
  # RBAC: sensors:view for page; rules:manage for management actions
end
```

#### `RulesLive.RulesetsLive` — Rulesets List Page (`/rules/rulesets`)

```elixir
defmodule ConfigManagerWeb.RulesLive.RulesetsLive do
  use ConfigManagerWeb, :live_view

  # Mount: load rulesets with effective counts and pool counts
  # Assigns: rulesets, current_user
  # Events:
  #   "new_ruleset" — navigate to create form (rules:manage)
  # RBAC: sensors:view for page; rules:manage for create button
end
```

#### `RulesLive.RulesetDetailLive` — Ruleset Detail Page (`/rules/rulesets/:id`)

```elixir
defmodule ConfigManagerWeb.RulesLive.RulesetDetailLive do
  use ConfigManagerWeb, :live_view

  # Mount: load ruleset with overrides, effective rule count, pool assignments
  # Assigns: ruleset, effective_count, pool_assignments, all_pools,
  #          editing, changeset, current_user
  # Events:
  #   "edit" — enter edit mode (rules:manage)
  #   "save" — update ruleset (rules:manage)
  #   "cancel_edit" — exit edit mode
  #   "delete" — delete ruleset with confirmation (rules:manage)
  #   "assign_pool" — assign ruleset to pool (rules:manage)
  #   "unassign_pool" — remove pool assignment (rules:manage)
  #   "deploy_to_pool" — deploy ruleset to pool (rules:deploy)
  #   "add_override" — add SID include/exclude (rules:manage)
  #   "remove_override" — remove SID override (rules:manage)
  # RBAC: sensors:view for page; rules:manage for edit/assign; rules:deploy for deploy
end
```

#### `RulesLive.DeploymentsLive` — Rule Deployments Page (`/rules/deployments`)

```elixir
defmodule ConfigManagerWeb.RulesLive.DeploymentsLive do
  use ConfigManagerWeb, :live_view

  # Mount: load rule deployment history from audit log
  # Assigns: deployments, page, total_pages, current_user
  # Events: "page" — pagination
  # Queries: audit_log WHERE action IN ["rules_deployed", "adhoc_rules_deployed"]
  # RBAC: sensors:view for page
end
```

### 11. Router Changes

New rule store routes added to the authenticated scope:

```elixir
# Inside the authenticated live_session block, after existing routes:
live "/rules/store", RulesLive.StoreLive, :index, private: %{required_permission: "sensors:view"}
live "/rules/categories", RulesLive.CategoriesLive, :index, private: %{required_permission: "sensors:view"}
live "/rules/repositories", RulesLive.RepositoriesLive, :index, private: %{required_permission: "sensors:view"}
live "/rules/rulesets", RulesLive.RulesetsLive, :index, private: %{required_permission: "sensors:view"}
live "/rules/rulesets/new", RulesLive.RulesetDetailLive, :new, private: %{required_permission: "rules:manage"}
live "/rules/rulesets/:id", RulesLive.RulesetDetailLive, :show, private: %{required_permission: "sensors:view"}
live "/rules/rulesets/:id/edit", RulesLive.RulesetDetailLive, :edit, private: %{required_permission: "rules:manage"}
live "/rules/deployments", RulesLive.DeploymentsLive, :index, private: %{required_permission: "sensors:view"}

# Existing route preserved:
live "/rules", RuleDeploymentLive, :index
```

Permission mapping:

| Route | Permission |
|-------|-----------|
| `/rules/store` | `sensors:view` (toggle checks `rules:manage` in `handle_event`) |
| `/rules/categories` | `sensors:view` (toggle checks `rules:manage` in `handle_event`) |
| `/rules/repositories` | `sensors:view` (write actions check `rules:manage` in `handle_event`) |
| `/rules/rulesets` | `sensors:view` |
| `/rules/rulesets/new` | `rules:manage` |
| `/rules/rulesets/:id` | `sensors:view` (edit/assign/deploy check in `handle_event`) |
| `/rules/rulesets/:id/edit` | `rules:manage` |
| `/rules/deployments` | `sensors:view` |
| `/rules` | existing (quick deploy, checks `rules:deploy` in `handle_event`) |

### 12. PubSub Topics and Messages

| Topic | Message | Triggered By |
|-------|---------|-------------|
| `"rules"` | `{:rules_updated, repo_id}` | `Rules.bulk_upsert_rules/3` |
| `"rules"` | `{:rule_toggled, rule_id}` | `Rules.toggle_rule/2` |
| `"rules"` | `{:category_toggled, category_name}` | `Rules.toggle_category/3` |
| `"rule_repositories"` | `{:repository_created, repo}` | `Rules.create_repository/2` |
| `"rule_repositories"` | `{:repository_updating, repo_id}` | `Rules.update_repository/2` |
| `"rule_repositories"` | `{:repository_updated, repo_id}` | Async fetch task completion |
| `"rule_repositories"` | `{:repository_update_failed, repo_id, error}` | Async fetch task failure |
| `"rule_repositories"` | `{:repository_deleted, repo_id}` | `Rules.delete_repository/2` |
| `"rulesets"` | `{:ruleset_created, ruleset}` | `Rules.create_ruleset/2` |
| `"rulesets"` | `{:ruleset_updated, ruleset}` | `Rules.update_ruleset/3` |
| `"rulesets"` | `{:ruleset_deleted, ruleset_id}` | `Rules.delete_ruleset/2` |
| `"rulesets"` | `{:ruleset_assigned, pool_id, ruleset_id}` | `Rules.assign_ruleset_to_pool/3` |
| `"rulesets"` | `{:ruleset_unassigned, pool_id}` | `Rules.unassign_ruleset_from_pool/2` |
| `"rulesets"` | `{:rules_deployed, pool_id, version}` | `Rules.deploy_ruleset_to_pool/3` |

### 13. Audit Entry Patterns

| Action | target_type | target_id | Detail Fields |
|--------|------------|-----------|---------------|
| `rule_toggled` | `suricata_rule` | rule.id | `%{sid, previous_state, new_state}` |
| `bulk_rules_toggled` | `rule_store` | `"bulk"` | `%{count, new_state, sids: [list]}` |
| `category_toggled` | `rule_category` | category_name | `%{category, affected_count, new_state}` |
| `repository_added` | `rule_repository` | repo.id | `%{name, url, repo_type}` |
| `repository_updated` | `rule_repository` | repo.id | `%{name, added, updated, unchanged}` |
| `repository_update_failed` | `rule_repository` | repo.id | `%{name, error}` |
| `repository_deleted` | `rule_repository` | repo.id | `%{name, preserved_rule_count}` |
| `ruleset_created` | `ruleset` | ruleset.id | `%{name, categories, override_count}` |
| `ruleset_updated` | `ruleset` | ruleset.id | `%{name, changes, version}` |
| `ruleset_deleted` | `ruleset` | ruleset.id | `%{name, affected_pool_count}` |
| `ruleset_assigned_to_pool` | `pool` | pool.id | `%{pool_name, ruleset_name, ruleset_id}` |
| `ruleset_unassigned_from_pool` | `pool` | pool.id | `%{pool_name, previous_ruleset_name}` |
| `rules_deployed` | `pool` | pool.id | `%{pool_name, ruleset_name, version, sensor_results}` |
| `adhoc_rules_deployed` | `pool` or `sensor_pod` | target_id | `%{target, filename, rule_count}` |

### 14. Navigation Integration Updates

**Main nav bar**: The existing "Rules" link is expanded into a dropdown/section with sub-links:
- Rule Store (`/rules/store`)
- Categories (`/rules/categories`)
- Repositories (`/rules/repositories`)
- Rulesets (`/rules/rulesets`)
- Deployments (`/rules/deployments`)
- Quick Deploy (`/rules`) — the existing paste-and-deploy page

**Pool detail page** (`PoolShowLive`): Display the assigned Ruleset name (linked to `/rules/rulesets/:id`) and sync status badge. Show "Deploy Rules" button when a ruleset is assigned and user has `rules:deploy`.

**Sensor detail page** (`SensorDetailLive`): Display `last_deployed_rule_version` in the identity or detection section.

**Existing rule deployment page** (`RuleDeploymentLive`): Add a banner/link at the top: "Looking for managed rulesets? Go to Rule Store →". Update pool dropdown to show pool names via `Pools.pool_name_map()`.

## Data Models

### New Tables Migration

```elixir
defmodule ConfigManager.Repo.Migrations.CreateRuleStoreTables do
  use Ecto.Migration

  def up do
    # ── suricata_rules ─────────────────────────────────────────────────────
    create table(:suricata_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :sid, :integer, null: false
      add :message, :text
      add :raw_text, :text, null: false
      add :category, :string, null: false
      add :classtype, :string
      add :severity, :integer, null: false, default: 2
      add :revision, :integer, null: false, default: 1
      add :enabled, :boolean, null: false, default: true
      add :repository_id, :binary_id
      add :repository_name, :string

      timestamps()
    end

    create unique_index(:suricata_rules, [:sid])
    create index(:suricata_rules, [:category])
    create index(:suricata_rules, [:enabled])
    create index(:suricata_rules, [:repository_id])

    # ── rule_repositories ──────────────────────────────────────────────────
    create table(:rule_repositories, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :url, :text, null: false
      add :repo_type, :string, null: false, default: "custom"
      add :last_updated_at, :utc_datetime
      add :last_update_status, :string, null: false, default: "never_updated"
      add :last_update_error, :text
      add :rule_count, :integer, null: false, default: 0

      timestamps()
    end

    execute "CREATE UNIQUE INDEX rule_repositories_name_nocase_index ON rule_repositories (name COLLATE NOCASE)"

    # ── rulesets ───────────────────────────────────────────────────────────
    create table(:rulesets, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :version, :integer, null: false, default: 1
      add :categories, :text, null: false, default: "[]"  # JSON array stored as text
      add :updated_by, :string

      timestamps()
    end

    execute "CREATE UNIQUE INDEX rulesets_name_nocase_index ON rulesets (name COLLATE NOCASE)"

    # ── ruleset_rules (SID overrides) ──────────────────────────────────────
    create table(:ruleset_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ruleset_id, references(:rulesets, type: :binary_id, on_delete: :delete_all), null: false
      add :sid, :integer, null: false
      add :action, :string, null: false  # "include" or "exclude"

      timestamps()
    end

    create unique_index(:ruleset_rules, [:ruleset_id, :sid])
    create index(:ruleset_rules, [:ruleset_id])

    # ── pool_ruleset_assignments ───────────────────────────────────────────
    create table(:pool_ruleset_assignments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :pool_id, references(:sensor_pools, type: :binary_id, on_delete: :delete_all), null: false
      add :ruleset_id, references(:rulesets, type: :binary_id, on_delete: :delete_all), null: false
      add :assigned_by, :string, null: false
      add :deployed_rule_version, :integer

      timestamps()
    end

    create unique_index(:pool_ruleset_assignments, [:pool_id])
    create index(:pool_ruleset_assignments, [:ruleset_id])
  end

  def down do
    drop table(:pool_ruleset_assignments)
    drop table(:ruleset_rules)
    execute "DROP INDEX IF EXISTS rulesets_name_nocase_index"
    drop table(:rulesets)
    execute "DROP INDEX IF EXISTS rule_repositories_name_nocase_index"
    drop table(:rule_repositories)
    drop table(:suricata_rules)
  end
end
```

### SensorPod Extension

A separate migration adds the `last_deployed_rule_version` field to `sensor_pods`:

```elixir
defmodule ConfigManager.Repo.Migrations.AddRuleVersionToSensorPods do
  use Ecto.Migration

  def change do
    alter table(:sensor_pods) do
      add :last_deployed_rule_version, :integer
    end
  end
end
```

### Entity Relationship Diagram

```mermaid
erDiagram
    RULE_REPOSITORIES ||--o{ SURICATA_RULES : "source of"
    RULESETS ||--o{ RULESET_RULES : "has overrides"
    RULESETS ||--o{ POOL_RULESET_ASSIGNMENTS : "assigned to"
    SENSOR_POOLS ||--o| POOL_RULESET_ASSIGNMENTS : "has assignment"
    SENSOR_POOLS ||--o{ SENSOR_PODS : "has members"

    SURICATA_RULES {
        binary_id id PK
        integer sid UK
        text message
        text raw_text
        string category
        string classtype
        integer severity
        integer revision
        boolean enabled
        binary_id repository_id FK
        string repository_name
        datetime inserted_at
        datetime updated_at
    }

    RULE_REPOSITORIES {
        binary_id id PK
        string name UK "COLLATE NOCASE"
        text url
        string repo_type
        datetime last_updated_at
        string last_update_status
        text last_update_error
        integer rule_count
        datetime inserted_at
        datetime updated_at
    }

    RULESETS {
        binary_id id PK
        string name UK "COLLATE NOCASE"
        text description
        integer version
        text categories "JSON array"
        string updated_by
        datetime inserted_at
        datetime updated_at
    }

    RULESET_RULES {
        binary_id id PK
        binary_id ruleset_id FK
        integer sid
        string action "include or exclude"
        datetime inserted_at
        datetime updated_at
    }

    POOL_RULESET_ASSIGNMENTS {
        binary_id id PK
        binary_id pool_id FK UK
        binary_id ruleset_id FK
        string assigned_by
        integer deployed_rule_version
        datetime inserted_at
        datetime updated_at
    }

    SENSOR_POOLS {
        binary_id id PK
        string name
        string capture_mode
        integer config_version
    }

    SENSOR_PODS {
        binary_id id PK
        string name
        binary_id pool_id FK
        integer last_deployed_rule_version "NEW"
    }
```


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Suricata rule parsing round-trip

*For any* valid Suricata rule line containing a `sid` keyword, parsing the line via `Parser.parse_rule/1` SHALL produce a rule data map with a positive integer SID, and formatting that map back via `Parser.format_rule/1` then re-parsing SHALL produce an equivalent SID and message. The raw_text field SHALL always contain the original rule line.

**Validates: Requirements 5.1, 5.2**

### Property 2: SID-based upsert preserves enabled state and is idempotent

*For any* existing rule with SID `S` and enabled state `E`, upserting a rule with the same SID and revision >= the stored revision SHALL preserve the enabled state `E`. Upserting the same rule data twice SHALL produce the same database state (idempotent). The total rule count after upserting N rules with M unique SIDs (M ≤ N) SHALL equal the previous count plus the number of new SIDs.

**Validates: Requirements 5.3, 5.5**

### Property 3: Rule toggle is its own inverse

*For any* rule with enabled state `E`, toggling the rule SHALL produce state `¬E`. Toggling again SHALL produce state `E`. The rule's SID, raw_text, category, and revision SHALL remain unchanged across both toggles.

**Validates: Requirements 2.1, 2.2**

### Property 4: Category toggle affects exactly the rules in that category

*For any* category `C` containing N rules, toggling the category to disabled SHALL set all N rules to disabled. The count of disabled rules in category `C` after the toggle SHALL equal N. Rules in other categories SHALL remain unchanged.

**Validates: Requirements 3.3, 3.4, 3.5**

### Property 5: Ruleset effective rule computation matches composition model

*For any* ruleset with included categories `[C1, C2, ...]`, explicit include SIDs `[I1, I2, ...]`, and explicit exclude SIDs `[E1, E2, ...]`, the effective rule set SHALL equal: `(enabled rules in C1 ∪ C2 ∪ ...) ∪ (rules with SID in I1, I2, ...) \ (rules with SID in E1, E2, ...)`. The effective rule count SHALL equal the cardinality of this set.

**Validates: Requirements 6.5**

### Property 6: Ruleset name uniqueness is case-insensitive

*For any* existing ruleset name `N`, attempting to create another ruleset with any case variant of `N` SHALL fail with a uniqueness validation error. The total number of rulesets SHALL remain unchanged.

**Validates: Requirements 6.4**

### Property 7: Ruleset version increments only on content changes

*For any* ruleset, updating only the name or description SHALL leave the version unchanged. Updating the categories list or SID overrides SHALL increment the version by exactly 1.

**Validates: Requirements 6.6**

### Property 8: One ruleset per pool invariant

*For any* pool, after assigning a ruleset, the pool SHALL have exactly one Pool_Ruleset_Assignment. Assigning a different ruleset SHALL replace the existing assignment (not create a second one). The total assignment count for the pool SHALL always be 0 or 1.

**Validates: Requirements 7.2**

### Property 9: Ruleset compilation produces valid rule file map

*For any* ruleset with at least one included category containing at least one enabled rule, compilation SHALL produce a non-empty map where every key ends in `.rules` and every value is a non-empty string. The total number of distinct SIDs across all compiled files SHALL equal the effective rule count. No SID SHALL appear in more than one file.

**Validates: Requirements 8.1**

### Property 10: Out-of-sync detection is correct

*For any* pool with an assigned ruleset at version V and sensors with various `last_deployed_rule_version` values, a sensor SHALL be classified as out-of-sync if and only if its `last_deployed_rule_version` is NULL or does not equal V. The out-of-sync count SHALL equal the number of sensors meeting this condition.

**Validates: Requirements 10.1, 10.2, 10.3**

### Property 11: Repository deletion preserves imported rules

*For any* repository with N imported rules, deleting the repository SHALL leave all N rules in the Rule Store. The total rule count SHALL remain unchanged. Each preserved rule's `repository_name` field SHALL still contain the deleted repository's name.

**Validates: Requirements 4.9**

### Property 12: Every rule store mutation produces an audit entry

*For any* successful rule store mutation (toggle, category toggle, repository add/update/delete, ruleset create/update/delete, assignment, deployment), the audit log SHALL contain at least one new entry with the correct action name, target type, and a non-empty detail field. The audit entry SHALL be written in the same transaction as the mutation.

**Validates: Requirements 12.1, 12.2, 12.3**
