//go:build linux

package main

import "testing"

func TestTPacketRingParamsAdjustsFrameCountToCompleteBlocks(t *testing.T) {
	blockSize, frameSize, frameNr, blockNr, err := tpacketRingParams(tpacketV3Config{
		BlockSizeMB: 4,
		FrameCount:  3000,
	})
	if err != nil {
		t.Fatalf("tpacketRingParams: %v", err)
	}

	if blockSize != 4*1024*1024 {
		t.Fatalf("blockSize = %d, want %d", blockSize, 4*1024*1024)
	}
	if frameSize != tpacketFrameSize {
		t.Fatalf("frameSize = %d, want %d", frameSize, tpacketFrameSize)
	}
	if blockNr != 2 {
		t.Fatalf("blockNr = %d, want 2", blockNr)
	}

	framesPerBlock := blockSize / frameSize
	if frameNr != blockNr*framesPerBlock {
		t.Fatalf("frameNr = %d, want complete block multiple %d", frameNr, blockNr*framesPerBlock)
	}
	if frameNr < 3000 {
		t.Fatalf("frameNr = %d, want at least requested frame count", frameNr)
	}
}

func TestTPacketRingParamsRejectsInvalidConfig(t *testing.T) {
	cases := []tpacketV3Config{
		{BlockSizeMB: 0, FrameCount: 2048},
		{BlockSizeMB: 4, FrameCount: 0},
	}

	for _, cfg := range cases {
		if _, _, _, _, err := tpacketRingParams(cfg); err == nil {
			t.Fatalf("tpacketRingParams(%+v) succeeded, want error", cfg)
		}
	}
}
