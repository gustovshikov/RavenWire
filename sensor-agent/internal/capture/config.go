//go:build linux

package capture

import (
	"encoding/json"
	"fmt"
	"os"
)

// FanoutMode represents a PACKET_FANOUT mode.
type FanoutMode string

const (
	FanoutHash       FanoutMode = "PACKET_FANOUT_HASH"
	FanoutRoundRobin FanoutMode = "PACKET_FANOUT_RR"
	FanoutCPU        FanoutMode = "PACKET_FANOUT_CPU"
	FanoutRollover   FanoutMode = "PACKET_FANOUT_ROLLOVER"
)

var validFanoutModes = map[FanoutMode]bool{
	FanoutHash:       true,
	FanoutRoundRobin: true,
	FanoutCPU:        true,
	FanoutRollover:   true,
}

// ConsumerConfig holds per-consumer AF_PACKET configuration.
type ConsumerConfig struct {
	Name          string     `json:"name"`
	FanoutGroupID uint16     `json:"fanout_group_id"`
	FanoutMode    FanoutMode `json:"fanout_mode"`
	Interface     string     `json:"interface"`
	BPFFilterPath string     `json:"bpf_filter_path,omitempty"`
	ThreadCount   int        `json:"thread_count"`
}

// CaptureConfig holds the full capture configuration for all consumers.
type CaptureConfig struct {
	Consumers []ConsumerConfig `json:"consumers"`
}

// OverrideInterface sets every capture consumer to the supplied interface.
// Node-specific interface names are deployment concerns, so CAPTURE_IFACE can
// safely override the checked-in template config at runtime.
func (c *CaptureConfig) OverrideInterface(iface string) {
	if iface == "" {
		return
	}
	for i := range c.Consumers {
		c.Consumers[i].Interface = iface
	}
}

// ValidationError describes a single configuration validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Validate checks the CaptureConfig for all invalid fields and returns all errors found.
// It checks for: duplicate fanout group IDs, invalid fanout modes, empty interface names,
// invalid thread counts, and empty consumer names.
func (c *CaptureConfig) Validate() []ValidationError {
	var errs []ValidationError

	if len(c.Consumers) == 0 {
		errs = append(errs, ValidationError{
			Field:   "consumers",
			Message: "at least one consumer must be configured",
		})
		return errs
	}

	// Check for duplicate fanout group IDs
	seen := make(map[uint16]string)
	for i, consumer := range c.Consumers {
		field := fmt.Sprintf("consumers[%d]", i)

		// Empty name
		if consumer.Name == "" {
			errs = append(errs, ValidationError{
				Field:   field + ".name",
				Message: "consumer name must not be empty",
			})
		}

		// Empty interface
		if consumer.Interface == "" {
			errs = append(errs, ValidationError{
				Field:   field + ".interface",
				Message: "interface name must not be empty",
			})
		}

		// Invalid fanout mode
		if !validFanoutModes[consumer.FanoutMode] {
			errs = append(errs, ValidationError{
				Field:   field + ".fanout_mode",
				Message: fmt.Sprintf("unknown fanout mode %q; valid modes: PACKET_FANOUT_HASH, PACKET_FANOUT_RR, PACKET_FANOUT_CPU, PACKET_FANOUT_ROLLOVER", consumer.FanoutMode),
			})
		}

		// Zero or negative thread count
		if consumer.ThreadCount <= 0 {
			errs = append(errs, ValidationError{
				Field:   field + ".thread_count",
				Message: fmt.Sprintf("thread_count must be >= 1, got %d", consumer.ThreadCount),
			})
		}

		// Duplicate fanout group ID
		if prev, exists := seen[consumer.FanoutGroupID]; exists {
			errs = append(errs, ValidationError{
				Field:   field + ".fanout_group_id",
				Message: fmt.Sprintf("fanout_group_id %d is already used by consumer %q; all fanout group IDs must be distinct", consumer.FanoutGroupID, prev),
			})
		} else {
			seen[consumer.FanoutGroupID] = consumer.Name
		}
	}

	return errs
}

// LoadCaptureConfig reads and parses a CaptureConfig from the given file path.
func LoadCaptureConfig(path string) (*CaptureConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read capture config %s: %w", path, err)
	}

	var cfg CaptureConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse capture config %s: %w", path, err)
	}

	return &cfg, nil
}

// DefaultCaptureConfigPath is the default location for the capture config file.
const DefaultCaptureConfigPath = "/etc/sensor/capture.conf"
