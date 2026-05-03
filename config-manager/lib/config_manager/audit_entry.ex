defmodule ConfigManager.AuditEntry do
  @moduledoc "Append-only audit log entry."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "audit_log" do
    field(:timestamp, :utc_datetime_usec)
    field(:actor, :string)
    field(:actor_type, :string)
    field(:action, :string)
    field(:target_type, :string)
    field(:target_id, :string)
    field(:result, :string)
    field(:detail, :string)
  end

  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [
      :timestamp,
      :actor,
      :actor_type,
      :action,
      :target_type,
      :target_id,
      :result,
      :detail
    ])
    |> validate_required([:timestamp, :actor, :actor_type, :action, :result])
    |> validate_inclusion(:actor_type, ~w(user api_token system anonymous))
    |> validate_inclusion(:result, ~w(success failure))
  end
end
