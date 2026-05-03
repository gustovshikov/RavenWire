defmodule ConfigManager.Enrollment.ReenrollmentTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias ConfigManager.{Enrollment, Repo, SensorPod}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  test "valid token can replace an existing pod enrollment record" do
    pod_name = "reenroll-pod-#{System.unique_integer([:positive])}"

    Repo.insert!(%SensorPod{
      name: pod_name,
      status: "enrolled",
      cert_serial: "OLD",
      cert_expires_at:
        DateTime.add(DateTime.utc_now(), -86_400, :second) |> DateTime.truncate(:second),
      cert_pem: "old cert",
      ca_chain_pem: "old ca",
      public_key_pem: "old key",
      key_fingerprint: "old fingerprint"
    })

    {:ok, token} = Enrollment.generate_token("test")
    {:ok, :pending} = Enrollment.submit(token, pod_name, public_key_pem("new"))

    pods = Repo.all(from(p in SensorPod, where: p.name == ^pod_name))
    assert length(pods) == 1

    [pod] = pods
    assert pod.status == "pending"
    assert pod.cert_serial == nil
    assert pod.cert_expires_at == nil
    assert pod.cert_pem == nil
    assert pod.ca_chain_pem == nil
    assert pod.public_key_pem == public_key_pem("new")
    assert pod.key_fingerprint != "old fingerprint"
  end

  defp public_key_pem(label) do
    """
    -----BEGIN PUBLIC KEY-----
    #{label}
    -----END PUBLIC KEY-----
    """
  end
end
