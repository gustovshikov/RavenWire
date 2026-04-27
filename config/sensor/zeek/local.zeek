# Zeek production configuration for Sensor_Pod
# Attaches to CAPTURE_IFACE with AF_PACKET fanout group 1
# Enables Community ID in all logs

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/ssh

# Enable JSON output for all logs
@load tuning/json-logs

# Community ID — required for cross-tool correlation
@load policy/protocols/conn/community-id-logging

# Write logs to the Quadlet-mounted handoff path consumed by Vector.
redef Log::default_logdir = "/logs/zeek";

# Log rotation: rotate every hour
redef Log::default_rotation_interval = 1hr;

# AF_PACKET configuration
# Interface and fanout group are set via command-line args:
#   zeek -i af_packet::<IFACE> local.zeek
# Fanout group 1 is set in the Zeek AF_PACKET plugin configuration.

# Disable DNS resolution in logs (use IPs for correlation)
redef Log::default_writer = Log::WRITER_ASCII;

# File extraction (for Strelka submission in v1)
# @load base/frameworks/files
# @load policy/frameworks/files/extract-all-files
