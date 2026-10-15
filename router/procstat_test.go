package main

import "testing"

func TestProcessStatus(t *testing.T) {
	v := processStatus()
	if v["rssMB"] == nil || v["peakRssMB"] == nil || v["goroutines"].(int) < 1 {
		t.Fatalf("process status: %v", v)
	}
}
