defmodule ConfigManager.Enrollment.CertRotationTest do
  use ExUnit.Case, async: false

  alias ConfigManager.{Enrollment, Repo, SensorPod}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  test "rotate_cert replaces the stored certificate bundle for an enrolled pod" do
    pod_name = "rotate-pod-#{System.unique_integer([:positive])}"
    old_public_key = public_key_pem()
    new_public_key = public_key_pem()

    old_pod =
      Repo.insert!(%SensorPod{
        name: pod_name,
        status: "enrolled",
        cert_serial: "OLD",
        cert_expires_at:
          DateTime.add(DateTime.utc_now(), 3_600, :second) |> DateTime.truncate(:second),
        cert_pem: "old cert",
        ca_chain_pem: "old ca",
        public_key_pem: old_public_key,
        key_fingerprint: "old fingerprint"
      })

    {:ok, bundle} = Enrollment.rotate_cert(pod_name, new_public_key)

    rotated = Repo.get!(SensorPod, old_pod.id)
    assert rotated.status == "enrolled"
    assert rotated.public_key_pem == new_public_key
    assert rotated.key_fingerprint != "old fingerprint"
    assert rotated.cert_serial != "OLD"
    assert rotated.cert_pem == bundle.cert_pem
    assert rotated.ca_chain_pem == bundle.ca_chain_pem
    assert DateTime.compare(rotated.cert_expires_at, DateTime.utc_now()) == :gt
  end

  defp public_key_pem do
    key = X509.PrivateKey.new_ec(:secp256r1)
    {:ECPrivateKey, _ver, _priv, curve, pub_point, _attrs} = key
    X509.PublicKey.to_pem({{:ECPoint, pub_point}, curve})
  end
end
