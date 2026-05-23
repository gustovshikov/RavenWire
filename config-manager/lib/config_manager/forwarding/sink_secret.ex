defmodule ConfigManager.Forwarding.SinkSecret do
  @moduledoc "Encrypted secret field associated with a forwarding sink."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Forwarding.ForwardingSink

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @secret_name_format ~r/^[a-zA-Z0-9._-]+$/

  schema "sink_secrets" do
    field(:secret_name, :string)
    field(:ciphertext, :string)
    field(:last_four, :string)

    belongs_to(:forwarding_sink, ForwardingSink)

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(secret, attrs) do
    secret
    |> cast(attrs, [:forwarding_sink_id, :secret_name, :ciphertext, :last_four])
    |> validate_required([:forwarding_sink_id, :secret_name, :ciphertext])
    |> validate_length(:secret_name, min: 1, max: 255)
    |> validate_format(:secret_name, @secret_name_format,
      message: "must contain only alphanumeric characters, hyphens, underscores, and periods"
    )
    |> validate_length(:last_four, max: 4)
    |> unique_constraint([:forwarding_sink_id, :secret_name],
      name: :sink_secrets_forwarding_sink_id_secret_name_index,
      message: "duplicate secret name for this sink"
    )
    |> foreign_key_constraint(:forwarding_sink_id)
  end
end
