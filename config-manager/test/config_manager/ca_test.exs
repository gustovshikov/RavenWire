defmodule ConfigManager.CATest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.CA.{CRLStore, IntermediateCA, Revocation}
  alias ConfigManager.{Repo, SensorPod}

  test "IntermediateCA issues leaf certificates for valid sensor public keys" do
    key = X509.PrivateKey.new_ec(:secp256r1)
    {:ECPrivateKey, _ver, _priv, curve, pub_point, _attrs} = key
    public_key_pem = X509.PublicKey.to_pem({{:ECPoint, pub_point}, curve})

    assert {:ok, bundle} = IntermediateCA.issue_leaf_cert("sensor-ca-test", public_key_pem)
    assert bundle.cert_pem =~ "BEGIN CERTIFICATE"
    assert bundle.ca_chain_pem =~ "BEGIN CERTIFICATE"
    assert is_binary(bundle.serial)
    assert %DateTime{} = bundle.expires_at
  end

  test "IntermediateCA rejects invalid public key PEM" do
    assert {:error, reason} = IntermediateCA.issue_leaf_cert("sensor-ca-test", "not a public key")
    assert reason =~ "invalid public key PEM"
  end

  test "CRLStore exposes current placeholder CRL and tracks revoked serials in ETS" do
    serial = "test-serial-#{System.unique_integer([:positive])}"

    assert {:ok, der} = CRLStore.current_crl_der()
    assert is_binary(der)
    assert {:ok, pem} = CRLStore.current_crl_pem()
    assert pem =~ "BEGIN X509 CRL" or pem =~ "BEGIN CRL"

    refute CRLStore.is_revoked?(serial)
    assert :ok = CRLStore.revoke(serial, :key_compromise)
    assert CRLStore.is_revoked?(serial)
  end

  test "Revocation returns clear errors for missing and uncertified pods" do
    assert {:error, :not_found} = Revocation.revoke_pod(Ecto.UUID.generate())

    pod =
      %SensorPod{}
      |> SensorPod.enrollment_changeset(%{
        name: "revocation-no-cert",
        public_key_pem: "public-key",
        key_fingerprint: "fingerprint"
      })
      |> Repo.insert!()

    assert {:error, :no_cert_to_revoke} = Revocation.revoke_pod(pod.id)
  end
end
