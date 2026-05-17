package main

import (
	"testing"

	"github.com/ravenwire/ravenwire/sensorctl/cmd"
)

func TestRootCommandIsConstructible(t *testing.T) {
	root := cmd.Root()
	if root.Use != "sensorctl" {
		t.Fatalf("root.Use = %q, want sensorctl", root.Use)
	}
}
