defmodule ConfigManager.Forwarding.DestinationValidatorPropertyTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Forwarding.DestinationValidator

  property "Property 9: Destination validation rejects blocked network addresses",
           [:verbose, numtests: 100] do
    forall code <- integer(1, 100_000) do
      {blocked_ip, blocked_reason} = blocked_ip_case(code)
      public_ip = public_ip_case(code)

      blocked_without_lab =
        blocked_ip
        |> http_url()
        |> DestinationValidator.validate("http", allow_private?: false)

      blocked_with_lab =
        blocked_ip
        |> http_url()
        |> DestinationValidator.validate("http", allow_private?: true)

      public_without_lab =
        public_ip
        |> http_url()
        |> DestinationValidator.validate("http", allow_private?: false)

      blocked_without_lab == {:error, blocked_reason} and
        blocked_with_lab == :ok and
        public_without_lab == :ok
    end
  end

  defp blocked_ip_case(code) do
    case rem(code, 8) do
      0 -> {"127.#{octet(code)}.#{octet(code * 2)}.#{octet(code * 3)}", :loopback}
      1 -> {"169.254.#{octet(code)}.#{octet(code * 2)}", :link_local}
      2 -> {"10.#{octet(code)}.#{octet(code * 2)}.#{octet(code * 3)}", :private_network}
      3 -> {"172.#{16 + rem(code, 16)}.#{octet(code)}.#{octet(code * 2)}", :private_network}
      4 -> {"192.168.#{octet(code)}.#{octet(code * 2)}", :private_network}
      5 -> {"::1", :loopback}
      6 -> {"fe80::#{hex16(code)}", :link_local}
      7 -> {"fc00::#{hex16(code)}", :private_network}
    end
  end

  defp public_ip_case(code) do
    "8.#{public_octet(code)}.#{public_octet(code * 2)}.#{public_octet(code * 3)}"
  end

  defp http_url(ip) do
    if String.contains?(ip, ":") do
      "https://[#{ip}]/collector"
    else
      "https://#{ip}/collector"
    end
  end

  defp octet(code), do: rem(code, 256)
  defp public_octet(code), do: rem(code, 254) + 1
  defp hex16(code), do: code |> rem(65_535) |> Integer.to_string(16)
end
