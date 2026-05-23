defmodule ConfigManager.Forwarding.DestinationValidatorTest do
  use ExUnit.Case, async: false

  alias ConfigManager.Forwarding.DestinationValidator

  setup do
    previous = System.get_env("ALLOW_PRIVATE_DESTINATIONS")

    on_exit(fn ->
      if previous do
        System.put_env("ALLOW_PRIVATE_DESTINATIONS", previous)
      else
        System.delete_env("ALLOW_PRIVATE_DESTINATIONS")
      end
    end)

    :ok
  end

  test "validates HTTP URL syntax and schemes" do
    assert :ok = DestinationValidator.validate("https://8.8.8.8/services/collector", "splunk_hec")
    assert {:error, :unsupported_scheme} = DestinationValidator.validate("ftp://8.8.8.8", "http")
    assert {:error, :malformed_url} = DestinationValidator.validate("not-a-url", "http")
  end

  test "validates host and port destination formats for syslog and kafka" do
    assert :ok = DestinationValidator.validate("8.8.8.8:514", "syslog")
    assert :ok = DestinationValidator.validate("8.8.8.8:9092,1.1.1.1:9092", "kafka")
    assert {:error, :invalid_port} = DestinationValidator.validate("8.8.8.8:99999", "syslog")
    assert {:error, :malformed_host} = DestinationValidator.validate("8.8.8.8", "kafka")
  end

  test "blocks loopback link-local and private addresses unless lab mode is enabled" do
    assert {:error, :loopback} = DestinationValidator.validate("https://127.0.0.1", "http")
    assert {:error, :link_local} = DestinationValidator.validate("https://169.254.1.10", "http")

    assert {:error, :private_network} =
             DestinationValidator.validate("https://192.168.1.10", "http")

    assert :ok =
             DestinationValidator.validate("https://127.0.0.1", "http", allow_private?: true)
  end

  test "reads allow-private lab mode from environment" do
    System.put_env("ALLOW_PRIVATE_DESTINATIONS", "true")

    assert DestinationValidator.allow_private?()
    assert :ok = DestinationValidator.validate("https://10.0.0.1", "http")

    System.put_env("ALLOW_PRIVATE_DESTINATIONS", "false")

    refute DestinationValidator.allow_private?()
    assert {:error, :private_network} = DestinationValidator.validate("https://10.0.0.1", "http")
  end

  test "allows absent S3 endpoint and validates provided endpoints" do
    assert :ok = DestinationValidator.validate(nil, "s3")
    assert :ok = DestinationValidator.validate("https://8.8.4.4", "s3")

    assert {:error, :unsupported_scheme} =
             DestinationValidator.validate("file:///tmp/bucket", "s3")
  end
end
