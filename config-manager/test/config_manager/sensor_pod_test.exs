defmodule ConfigManager.SensorPodTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.SensorPod

  test "enrollment changeset requires identity fields and accepts control API host" do
    changeset =
      SensorPod.enrollment_changeset(%SensorPod{}, %{
        name: "sensor-01",
        public_key_pem: "public-key",
        key_fingerprint: "fingerprint",
        control_api_host: "10.0.0.5"
      })

    assert changeset.valid?
    assert Ecto.Changeset.get_change(changeset, :control_api_host) == "10.0.0.5"

    invalid = SensorPod.enrollment_changeset(%SensorPod{}, %{})
    refute invalid.valid?
    assert %{name: [_], public_key_pem: [_], key_fingerprint: [_]} = errors_on(invalid)
  end

  test "reenrollment resets issued certificate state to pending" do
    pod = %SensorPod{
      status: "enrolled",
      cert_serial: "abc",
      cert_pem: "cert",
      ca_chain_pem: "chain",
      cert_expires_at: DateTime.utc_now()
    }

    changeset =
      SensorPod.reenrollment_changeset(pod, %{
        name: "sensor-01",
        public_key_pem: "new-public-key",
        key_fingerprint: "new-fingerprint"
      })

    assert changeset.valid?
    assert Ecto.Changeset.get_change(changeset, :status) == "pending"
    assert Ecto.Changeset.get_change(changeset, :cert_serial) == nil
    assert Ecto.Changeset.get_change(changeset, :cert_pem) == nil
    assert Ecto.Changeset.get_change(changeset, :ca_chain_pem) == nil
  end

  test "approval and rotation changesets enforce valid statuses" do
    approval =
      SensorPod.approval_changeset(%SensorPod{}, %{
        status: "enrolled",
        cert_serial: "abc",
        cert_expires_at: DateTime.utc_now()
      })

    assert approval.valid?

    invalid = SensorPod.approval_changeset(%SensorPod{}, %{status: "lost"})
    refute invalid.valid?
    assert %{status: [_], cert_serial: [_], cert_expires_at: [_]} = errors_on(invalid)
  end

  test "pcap config changeset validates numeric bounds and severity" do
    valid =
      SensorPod.pcap_config_changeset(%SensorPod{}, %{
        pcap_ring_size_mb: 1024,
        pre_alert_window_sec: 0,
        post_alert_window_sec: 30,
        alert_severity_threshold: 2
      })

    assert valid.valid?

    invalid =
      SensorPod.pcap_config_changeset(%SensorPod{}, %{
        pcap_ring_size_mb: 0,
        pre_alert_window_sec: -1,
        post_alert_window_sec: -1,
        alert_severity_threshold: 9
      })

    refute invalid.valid?

    assert %{
             pcap_ring_size_mb: [_],
             pre_alert_window_sec: [_],
             post_alert_window_sec: [_],
             alert_severity_threshold: [_]
           } =
             errors_on(invalid)
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
