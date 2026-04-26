# Zeek local configuration for spike validation
# Attaches to CAPTURE_IFACE with AF_PACKET fanout group 1
# Enables Community ID in all logs

@load base/frameworks/notice
@load base/protocols/conn
@load policy/frameworks/network/community-id

# AF_PACKET configuration is set via environment / command-line args:
#   zeek -i af_packet::<iface>
# The fanout group and cluster config are set in node.cfg / zeekctl.cfg.
# For the spike we drive Zeek directly with the af_packet plugin.

# Enable JSON output for all logs
@load tuning/json-logs

# Community ID — load the correct script for this Zeek version
@load policy/protocols/conn/community-id-logging

# Write logs to /logs/zeek/
redef Log::default_logdir = "/logs/zeek";

# Disable rotation for the spike (keep it simple)
redef Log::default_rotation_interval = 0secs;
