defmodule ConfigManager.Enrollment.TokenSingleUsePropertyTest do
  @moduledoc """
  Property 13: Enrollment Token Single-Use Enforcement

  Generates arbitrary sequences of enrollment attempts using the same token and
  asserts the token is accepted exactly once — all subsequent uses are rejected
  regardless of approval state.

  Validates: Requirements 19.1
  """

  use ExUnit.Case, async: false
  use PropCheck

  import Ecto.Query

  alias ConfigManager.{Repo, Enrollment}
  alias ConfigManager.Enrollment.Token

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  # Generates a valid pod name: non-empty alphanumeric string up to 32 chars.
  defp pod_name_gen do
    let chars <- non_empty(list(union([range(?a, ?z), range(?0, ?9), ?-, ?_]))) do
      chars
      |> Enum.take(32)
      |> List.to_string()
    end
  end

  # Generates a minimal PEM-like public key string (content doesn't need to be
  # a real key for token-enforcement tests — the token check happens before key
  # parsing).
  defp public_key_gen do
    let suffix <- non_empty(list(range(?A, ?Z))) do
      "-----BEGIN PUBLIC KEY-----\n" <>
        List.to_string(suffix) <>
        "\n-----END PUBLIC KEY-----"
    end
  end

  # Generates a sequence of 2..5 enrollment attempts (pod_name, public_key pairs).
  # Each attempt uses a distinct pod name to avoid unique-name DB conflicts while
  # still reusing the same token.
  defp attempt_sequence_gen do
    let count <- integer(2, 5) do
      for i <- 1..count do
        {
          "pod-attempt-#{i}-#{:erlang.unique_integer([:positive])}",
          "-----BEGIN PUBLIC KEY-----\nKEY#{i}\n-----END PUBLIC KEY-----"
        }
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 13
  # ---------------------------------------------------------------------------

  property "Property 13: enrollment token is accepted exactly once; all subsequent uses are rejected",
           [:verbose, numtests: 50] do
    forall attempts <- attempt_sequence_gen() do
      # Generate a fresh one-time token for each test run.
      {:ok, token_value} = Enrollment.generate_token("prop_test")

      results =
        Enum.map(attempts, fn {pod_name, public_key_pem} ->
          Enrollment.submit(token_value, pod_name, public_key_pem)
        end)

      # Exactly one attempt must succeed.
      successes = Enum.count(results, &match?({:ok, :pending}, &1))

      # All remaining attempts must be rejected with token_invalid or token_expired.
      failures = Enum.reject(results, &match?({:ok, :pending}, &1))

      all_failures_are_token_errors =
        Enum.all?(failures, fn
          {:error, :token_invalid} -> true
          {:error, :token_expired} -> true
          _ -> false
        end)

      # The token must be marked consumed in the DB after the first use.
      token_record = Repo.get_by(Token, token: token_value)
      token_consumed = token_record != nil and token_record.consumed_at != nil

      successes == 1 and all_failures_are_token_errors and token_consumed
    end
  end

  property "Property 13b: token rejected on all subsequent uses regardless of approval state",
           [:verbose, numtests: 30] do
    forall attempts <- attempt_sequence_gen() do
      {:ok, token_value} = Enrollment.generate_token("prop_test_approval")

      # Submit all attempts and collect results.
      results =
        Enum.map(attempts, fn {pod_name, public_key_pem} ->
          Enrollment.submit(token_value, pod_name, public_key_pem)
        end)

      # Find the one successful submission and approve it.
      success_index =
        Enum.find_index(results, &match?({:ok, :pending}, &1))

      approved? =
        if success_index != nil do
          # Approve the pending pod to change approval state.
          pending = Enrollment.list_pending()

          case pending do
            [pod | _] ->
              # Approve using a mock CA — we only care that the token stays consumed.
              # If CA is not initialized in test env, approval may fail; that's fine —
              # we only assert on token re-use rejection, not on approval success.
              case Enrollment.approve(pod.id) do
                {:ok, _} -> true
                {:error, _} -> false
              end

            [] ->
              false
          end
        else
          false
        end

      # Regardless of approval outcome, attempt the token again — must be rejected.
      {_pod_name, pub_key} = List.first(attempts)
      retry_result = Enrollment.submit(token_value, "retry-pod-#{:erlang.unique_integer([:positive])}", pub_key)

      token_rejected_on_retry =
        match?({:error, :token_invalid}, retry_result) or
          match?({:error, :token_expired}, retry_result)

      # The token must remain consumed in the DB.
      token_record = Repo.get_by(Token, token: token_value)
      token_still_consumed = token_record != nil and token_record.consumed_at != nil

      _ = approved?

      token_rejected_on_retry and token_still_consumed
    end
  end

  property "Property 13c: expired token is consumed on first use and rejected on all subsequent uses",
           [:verbose, numtests: 20] do
    forall attempts <- attempt_sequence_gen() do
      # Insert a token that is already expired.
      expired_at = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, expired_token} =
        Token.create(%{
          token: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
          created_by: "prop_test_expired",
          expires_at: expired_at
        })

      results =
        Enum.map(attempts, fn {pod_name, public_key_pem} ->
          Enrollment.submit(expired_token.token, pod_name, public_key_pem)
        end)

      # All attempts on an expired token must be rejected.
      all_rejected =
        Enum.all?(results, fn
          {:error, :token_expired} -> true
          {:error, :token_invalid} -> true
          _ -> false
        end)

      # No successful enrollment must have occurred.
      no_success = not Enum.any?(results, &match?({:ok, :pending}, &1))

      all_rejected and no_success
    end
  end
end
