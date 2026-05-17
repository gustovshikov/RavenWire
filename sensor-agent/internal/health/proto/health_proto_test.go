package proto

import "testing"

func TestGeneratedHealthReportGettersReturnFieldsAndDefaults(t *testing.T) {
	report := &HealthReport{SensorPodId: "sensor-01", TimestampUnixMs: 123}

	if report.GetSensorPodId() != "sensor-01" {
		t.Fatalf("GetSensorPodId() = %q", report.GetSensorPodId())
	}
	if report.GetTimestampUnixMs() != 123 {
		t.Fatalf("GetTimestampUnixMs() = %d", report.GetTimestampUnixMs())
	}

	var nilReport *HealthReport
	if nilReport.GetSensorPodId() != "" || nilReport.GetTimestampUnixMs() != 0 {
		t.Fatal("nil HealthReport getters should return zero values")
	}
}
