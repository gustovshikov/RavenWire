defmodule ConfigManager.Forwarding do
  @moduledoc "Pool-scoped forwarding sink management context."

  import Ecto.Query

  alias ConfigManager.Forwarding.{
    ConnectionTester,
    Encryption,
    ForwardingSink,
    SinkConfigSchema,
    SinkSecret
  }

  alias ConfigManager.{Audit, Repo, SensorPool}
  alias Ecto.Multi

  def list_sinks(pool_id) do
    Repo.all(
      from(s in ForwardingSink,
        where: s.pool_id == ^pool_id,
        order_by: [asc: s.normalized_name, asc: s.inserted_at]
      )
    )
  end

  def get_sink(sink_id), do: Repo.get(ForwardingSink, sink_id)

  def get_sink_for_pool(pool_id, sink_id) do
    case Repo.get_by(ForwardingSink, id: sink_id, pool_id: pool_id) do
      nil -> {:error, :not_found}
      sink -> {:ok, sink}
    end
  end

  def change_sink(%ForwardingSink{} = sink, attrs \\ %{}) do
    ForwardingSink.update_changeset(sink, attrs)
  end

  def create_sink(pool_id, attrs, actor) do
    attrs = normalize_attrs(attrs)
    actor = actor_name(actor)

    with %SensorPool{} = pool <- Repo.get(SensorPool, pool_id),
         {:ok, sink_attrs, secrets} <- build_sink_attrs(pool, attrs, nil),
         {:ok, secret_attrs} <- encrypt_secret_attrs(secrets) do
      Multi.new()
      |> Multi.insert(:sink, ForwardingSink.create_changeset(%ForwardingSink{}, sink_attrs))
      |> insert_secret_changes(secret_attrs)
      |> Multi.update(:pool, SensorPool.increment_forwarding_version_changeset(pool, actor))
      |> Audit.append_multi(fn %{sink: sink} ->
        audit_attrs(actor, "sink_created", "forwarding_sink", sink.id, %{
          name: sink.name,
          sink_type: sink.sink_type,
          pool_id: pool.id,
          pool_name: pool.name,
          secrets_present: Map.keys(secret_attrs)
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{sink: sink}} ->
          broadcast_forwarding(pool.id, {:sink_created, sink})
          {:ok, sink}

        {:error, :sink, changeset, _changes} ->
          {:error, changeset}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    else
      nil ->
        {:error, :pool_not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def update_sink(pool_id, sink_id, attrs, actor) do
    attrs = normalize_attrs(attrs)
    actor = actor_name(actor)

    with {:ok, sink} <- get_sink_for_pool(pool_id, sink_id),
         %SensorPool{} = pool <- Repo.get(SensorPool, pool_id),
         {:ok, sink_attrs, secrets} <- build_sink_attrs(pool, attrs, sink),
         {:ok, secret_attrs} <- encrypt_secret_attrs(secrets) do
      changeset = ForwardingSink.update_changeset(sink, sink_attrs)
      changed? = changeset.changes != %{} or secret_attrs != %{}

      if changed? do
        Multi.new()
        |> Multi.update(:sink, changeset)
        |> upsert_secret_changes(secret_attrs)
        |> Multi.update(:pool, SensorPool.increment_forwarding_version_changeset(pool, actor))
        |> Audit.append_multi(fn %{sink: updated} ->
          audit_attrs(actor, "sink_updated", "forwarding_sink", updated.id, %{
            changes: changed_fields(sink, updated),
            secrets_changed: Map.keys(secret_attrs),
            pool_id: pool.id,
            pool_name: pool.name
          })
        end)
        |> Repo.transaction()
        |> case do
          {:ok, %{sink: updated}} ->
            broadcast_forwarding(pool.id, {:sink_updated, updated})
            {:ok, updated}

          {:error, :sink, changeset, _changes} ->
            {:error, changeset}

          {:error, _step, reason, _changes} ->
            {:error, reason}
        end
      else
        {:ok, sink}
      end
    else
      nil ->
        {:error, :pool_not_found}

      {:error, :not_found} ->
        audit_cross_pool_failure(pool_id, sink_id, actor, "sink_updated")
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def delete_sink(pool_id, sink_id, actor) do
    actor = actor_name(actor)

    with {:ok, sink} <- get_sink_for_pool(pool_id, sink_id),
         %SensorPool{} = pool <- Repo.get(SensorPool, pool_id) do
      Multi.new()
      |> Multi.delete(:sink, sink)
      |> Multi.update(:pool, SensorPool.increment_forwarding_version_changeset(pool, actor))
      |> Audit.append_multi(fn _changes ->
        audit_attrs(actor, "sink_deleted", "forwarding_sink", sink.id, %{
          name: sink.name,
          sink_type: sink.sink_type,
          pool_id: pool.id,
          pool_name: pool.name
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{sink: deleted}} ->
          broadcast_forwarding(pool.id, {:sink_deleted, deleted.id})
          {:ok, deleted}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    else
      nil ->
        {:error, :pool_not_found}

      {:error, :not_found} ->
        audit_cross_pool_failure(pool_id, sink_id, actor, "sink_deleted")
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def toggle_sink(pool_id, sink_id, actor) do
    actor = actor_name(actor)

    with {:ok, sink} <- get_sink_for_pool(pool_id, sink_id),
         %SensorPool{} = pool <- Repo.get(SensorPool, pool_id) do
      Multi.new()
      |> Multi.update(:sink, ForwardingSink.toggle_changeset(sink))
      |> Multi.update(:pool, SensorPool.increment_forwarding_version_changeset(pool, actor))
      |> Audit.append_multi(fn %{sink: updated} ->
        audit_attrs(actor, "sink_toggled", "forwarding_sink", updated.id, %{
          name: updated.name,
          enabled: updated.enabled,
          pool_id: pool.id,
          pool_name: pool.name
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{sink: updated}} ->
          broadcast_forwarding(pool.id, {:sink_toggled, updated})
          {:ok, updated}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    else
      nil ->
        {:error, :pool_not_found}

      {:error, :not_found} ->
        audit_cross_pool_failure(pool_id, sink_id, actor, "sink_toggled")
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def update_schema_mode(pool_id, schema_mode, actor) do
    actor = actor_name(actor)

    case Repo.get(SensorPool, pool_id) do
      nil ->
        {:error, :pool_not_found}

      %SensorPool{} = pool ->
        changeset = SensorPool.schema_mode_changeset(pool, %{schema_mode: schema_mode}, actor)

        if changeset.valid? and changeset.changes == %{} do
          {:ok, pool}
        else
          Multi.new()
          |> Multi.update(:pool, changeset)
          |> Audit.append_multi(fn %{pool: updated} ->
            audit_attrs(actor, "schema_mode_changed", "pool", updated.id, %{
              old_mode: pool.schema_mode,
              new_mode: updated.schema_mode,
              pool_name: updated.name
            })
          end)
          |> Repo.transaction()
          |> case do
            {:ok, %{pool: updated}} ->
              broadcast_forwarding(pool.id, {:schema_mode_changed, updated.schema_mode})
              {:ok, updated}

            {:error, :pool, changeset, _changes} ->
              {:error, changeset}

            {:error, _step, reason, _changes} ->
              {:error, reason}
          end
        end
    end
  end

  def test_connection(pool_id, sink_id, caller_pid, opts \\ []) when is_pid(caller_pid) do
    opts = normalize_opts(opts)
    actor = actor_name(Keyword.get(opts, :actor, "system"))

    with {:ok, sink} <- get_sink_for_pool(pool_id, sink_id),
         %SensorPool{} = pool <- Repo.get(SensorPool, pool_id) do
      on_result = Keyword.get(opts, :on_result)

      connection_opts =
        opts
        |> Keyword.put(:on_result, fn tested_sink, result ->
          sanitized_result = sanitize_test_result(result)
          _ = record_connection_test_result(pool, tested_sink, sanitized_result, actor)
          _ = run_external_result_callback(on_result, tested_sink, sanitized_result, opts)
          sanitized_result
        end)

      ConnectionTester.test_async(sink, caller_pid, connection_opts)
    else
      nil ->
        {:error, :pool_not_found}

      {:error, :not_found} ->
        audit_cross_pool_failure(pool_id, sink_id, actor, "sink_connection_tested")
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def record_test_result(pool_id, sink_id, result, tested_at \\ DateTime.utc_now()) do
    sanitized_result = sanitize_test_result(result)

    with {:ok, sink} <- get_sink_for_pool(pool_id, sink_id),
         changeset <- ForwardingSink.test_result_changeset(sink, sanitized_result, tested_at),
         {:ok, updated} <- Repo.update(changeset) do
      broadcast_forwarding(pool_id, {:connection_test_complete, sink_id, sanitized_result})
      {:ok, updated}
    end
  end

  defp record_connection_test_result(
         %SensorPool{} = pool,
         %ForwardingSink{} = sink,
         result,
         actor
       ) do
    tested_at = DateTime.utc_now()
    sanitized_result = sanitize_test_result(result)

    Multi.new()
    |> Multi.update(
      :sink,
      ForwardingSink.test_result_changeset(sink, sanitized_result, tested_at)
    )
    |> Audit.append_multi(fn %{sink: updated} ->
      audit_attrs(actor, "sink_connection_tested", "forwarding_sink", updated.id, %{
        name: updated.name,
        sink_type: updated.sink_type,
        pool_id: pool.id,
        pool_name: pool.name,
        result: if(truthy_result?(sanitized_result), do: "success", else: "failure"),
        error_category:
          Map.get(sanitized_result, :error_category) ||
            Map.get(sanitized_result, "error_category"),
        message: Map.get(sanitized_result, :message) || Map.get(sanitized_result, "message"),
        endpoint: Map.get(sanitized_result, :endpoint) || Map.get(sanitized_result, "endpoint")
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{sink: updated}} ->
        broadcast_forwarding(pool.id, {:connection_test_complete, sink.id, sanitized_result})
        {:ok, updated}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def masked_secrets(sink_id) do
    Repo.all(
      from(s in SinkSecret,
        where: s.forwarding_sink_id == ^sink_id,
        order_by: [asc: s.secret_name]
      )
    )
    |> Enum.map(fn secret ->
      %{
        secret_name: secret.secret_name,
        masked: Encryption.mask_last_four(secret.last_four || "")
      }
    end)
  end

  def get_schema_mode(pool_id) do
    Repo.one(from(p in SensorPool, where: p.id == ^pool_id, select: p.schema_mode))
  end

  def forwarding_summary(pool_id) do
    pool = Repo.get!(SensorPool, pool_id)

    counts =
      Repo.one(
        from(s in ForwardingSink,
          where: s.pool_id == ^pool_id,
          select: %{total: count(s.id), enabled: filter(count(s.id), s.enabled == true)}
        )
      )

    %{
      sink_count: counts.total || 0,
      enabled_count: counts.enabled || 0,
      schema_mode: pool.schema_mode,
      forwarding_config_version: pool.forwarding_config_version,
      forwarding_config_updated_at: pool.forwarding_config_updated_at,
      forwarding_config_updated_by: pool.forwarding_config_updated_by
    }
  end

  defp build_sink_attrs(pool, attrs, nil) do
    sink_type = value(attrs, "sink_type")
    secrets = extract_secrets(sink_type, attrs)

    with {:ok, config} <- SinkConfigSchema.validate(sink_type, attrs),
         :ok <- validate_required_secrets(sink_type, attrs, secrets, nil),
         {:ok, encoded_config} <- Jason.encode(config) do
      sink_attrs = %{
        pool_id: pool.id,
        name: value(attrs, "name"),
        sink_type: sink_type,
        config: encoded_config,
        enabled: normalize_boolean(value(attrs, "enabled", true), true)
      }

      {:ok, sink_attrs, extract_secrets(sink_type, attrs)}
    else
      {:error, errors} when is_list(errors) ->
        {:error, validation_changeset(errors)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_sink_attrs(%SensorPool{}, attrs, %ForwardingSink{} = sink) do
    sink_type = sink.sink_type
    secrets = extract_secrets(sink_type, attrs)

    with {:ok, config} <- SinkConfigSchema.validate(sink_type, attrs),
         :ok <- validate_required_secrets(sink_type, attrs, secrets, sink),
         {:ok, encoded_config} <- Jason.encode(config) do
      sink_attrs =
        %{
          name: value(attrs, "name", sink.name),
          config: encoded_config,
          enabled: normalize_boolean(value(attrs, "enabled", sink.enabled), sink.enabled)
        }

      {:ok, sink_attrs, secrets}
    else
      {:error, errors} when is_list(errors) ->
        {:error, validation_changeset(errors)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_required_secrets(sink_type, attrs, secrets, sink) do
    missing =
      sink_type
      |> SinkConfigSchema.required_secret_fields(attrs)
      |> Enum.reject(fn name ->
        Map.has_key?(secrets, name) or existing_secret?(sink, name)
      end)

    case missing do
      [] -> :ok
      fields -> {:error, Enum.map(fields, &{String.to_atom(&1), "can't be blank"})}
    end
  end

  defp existing_secret?(nil, _name), do: false

  defp existing_secret?(%ForwardingSink{} = sink, name) do
    Repo.exists?(
      from(s in SinkSecret, where: s.forwarding_sink_id == ^sink.id and s.secret_name == ^name)
    )
  end

  defp extract_secrets(sink_type, attrs) do
    fields = SinkConfigSchema.secret_fields(sink_type)

    attrs
    |> normalize_attrs()
    |> Map.take(fields)
    |> Enum.reject(fn {_field, value} -> blank_or_mask?(value) end)
    |> Map.new()
  end

  defp encrypt_secret_attrs(secrets) do
    Enum.reduce_while(secrets, {:ok, %{}}, fn {name, plaintext}, {:ok, acc} ->
      plaintext = to_string(plaintext)

      case Encryption.encrypt(plaintext) do
        {:ok, ciphertext} ->
          {:cont,
           {:ok,
            Map.put(acc, name, %{
              secret_name: name,
              ciphertext: ciphertext,
              last_four: Encryption.last_four(plaintext)
            })}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
  end

  defp insert_secret_changes(multi, secret_attrs) do
    Enum.reduce(secret_attrs, multi, fn {name, attrs}, multi ->
      Multi.insert(multi, {:secret, name}, fn %{sink: sink} ->
        SinkSecret.changeset(%SinkSecret{}, Map.put(attrs, :forwarding_sink_id, sink.id))
      end)
    end)
  end

  defp upsert_secret_changes(multi, secret_attrs) do
    Enum.reduce(secret_attrs, multi, fn {name, attrs}, multi ->
      Multi.run(multi, {:secret, name}, fn repo, %{sink: sink} ->
        existing = repo.get_by(SinkSecret, forwarding_sink_id: sink.id, secret_name: name)
        attrs = Map.put(attrs, :forwarding_sink_id, sink.id)

        case existing do
          nil -> repo.insert(SinkSecret.changeset(%SinkSecret{}, attrs))
          secret -> repo.update(SinkSecret.changeset(secret, attrs))
        end
      end)
    end)
  end

  defp changed_fields(old, new) do
    [:name, :config, :enabled]
    |> Enum.reduce(%{}, fn field, acc ->
      old_value = Map.get(old, field)
      new_value = Map.get(new, field)

      if old_value == new_value do
        acc
      else
        Map.put(acc, field, %{
          old: decode_config(field, old_value),
          new: decode_config(field, new_value)
        })
      end
    end)
  end

  defp decode_config(:config, value) when is_binary(value) do
    case Jason.decode(value) do
      {:ok, decoded} -> decoded
      _error -> value
    end
  end

  defp decode_config(_field, value), do: value

  defp validation_changeset(errors) do
    Enum.reduce(errors, ForwardingSink.create_changeset(%ForwardingSink{}, %{}), fn {field,
                                                                                     message},
                                                                                    changeset ->
      Ecto.Changeset.add_error(changeset, field, message)
    end)
  end

  defp sanitize_test_result(result) when is_map(result) do
    result
    |> Map.drop(["token", "password", "secret", :token, :password, :secret])
    |> scrub_message_fields()
    |> scrub_url_fields()
  end

  defp sanitize_test_result(result),
    do: %{message: ConnectionTester.sanitize_error_message(result)}

  defp scrub_message_fields(result) do
    Enum.reduce(result, %{}, fn {key, value}, acc ->
      sanitized =
        if to_string(key) in ["message", "error", "reason"] do
          ConnectionTester.sanitize_error_message(value)
        else
          value
        end

      Map.put(acc, key, sanitized)
    end)
  end

  defp scrub_url_fields(result) do
    Enum.reduce(result, %{}, fn {key, value}, acc ->
      normalized_key = to_string(key)

      sanitized =
        if String.contains?(normalized_key, "url") or String.contains?(normalized_key, "endpoint") do
          sanitize_url(value)
        else
          value
        end

      Map.put(acc, key, sanitized)
    end)
  end

  defp sanitize_url(value) do
    uri = value |> to_string() |> URI.parse()

    %URI{uri | userinfo: nil, query: nil, fragment: nil}
    |> URI.to_string()
  end

  defp run_external_result_callback(nil, _sink, _result, _opts), do: :ok

  defp run_external_result_callback(callback, sink, result, _opts) when is_function(callback, 2),
    do: callback.(sink, result)

  defp run_external_result_callback(callback, sink, result, opts) when is_function(callback, 3),
    do: callback.(sink, result, opts)

  defp run_external_result_callback(_callback, _sink, _result, _opts), do: :ok

  defp truthy_result?(result) when is_map(result) do
    Map.get(result, :success) || Map.get(result, "success") || false
  end

  defp truthy_result?(_result), do: false

  defp audit_attrs(actor, action, target_type, target_id, detail) do
    %{
      actor: actor,
      actor_type: "user",
      action: action,
      target_type: target_type,
      target_id: target_id,
      result: "success",
      detail: detail
    }
  end

  defp audit_cross_pool_failure(pool_id, sink_id, actor, action) do
    case Repo.get(ForwardingSink, sink_id) do
      %ForwardingSink{} = sink when sink.pool_id != pool_id ->
        _ =
          Audit.log(%{
            actor: actor,
            actor_type: "user",
            action: action,
            target_type: "forwarding_sink",
            target_id: sink.id,
            result: "failure",
            detail: %{
              reason: "sink_not_found_for_pool",
              attempted_pool_id: pool_id,
              sink_type: sink.sink_type,
              name: sink.name
            }
          })

        :ok

      _not_cross_pool ->
        :ok
    end
  end

  defp broadcast_forwarding(pool_id, message) do
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "pool:#{pool_id}:forwarding", message)
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "pools", {:forwarding_changed, pool_id})
  end

  defp normalize_attrs(%{} = attrs) do
    Enum.reduce(attrs, %{}, fn {key, value}, acc -> Map.put(acc, to_string(key), value) end)
  end

  defp normalize_attrs(_attrs), do: %{}

  defp normalize_opts(opts) when is_list(opts), do: opts
  defp normalize_opts(actor), do: [actor: actor]

  defp value(attrs, key, default \\ nil), do: Map.get(attrs, to_string(key), default)

  defp normalize_boolean(value, _default) when value in [true, "true", "1", 1, "on"], do: true
  defp normalize_boolean(value, _default) when value in [false, "false", "0", 0, "off"], do: false
  defp normalize_boolean(nil, default), do: default
  defp normalize_boolean(_value, default), do: default

  defp blank_or_mask?(value) when is_binary(value) do
    trimmed = String.trim(value)
    trimmed == "" or String.match?(trimmed, ~r/^\*+$/)
  end

  defp blank_or_mask?(nil), do: true
  defp blank_or_mask?(_value), do: false

  defp actor_name(%{username: username}), do: username
  defp actor_name(actor) when is_binary(actor) and actor != "", do: actor
  defp actor_name(_actor), do: "system"
end
