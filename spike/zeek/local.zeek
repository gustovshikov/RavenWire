# Zeek local configuration for spike validation
# Attaches to CAPTURE_IFACE with AF_PACKET fanout group 1
# Enables Community ID in all logs

@load base/frameworks/notice
@load base/protocols/conn

# Enable JSON output for all logs
@load tuning/json-logs

# Community ID — correct path for zeek/zeek:latest image
@load policy/protocols/conn/community-id-logging

# Write logs to /logs/zeek/
redef Log::default_logdir = "/logs/zeek";

# Disable rotation for the spike (keep it simple)
redef Log::default_rotation_interval = 0secs;
