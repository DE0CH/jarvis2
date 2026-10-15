package main

// The router process's own memory, for /setup/status (`process`): sizing the control box (Deyao, 2026-10-15: measure
// the router's real memory before sizing the box) and seeing a leak, on a box with no other way in. VmRSS and VmHWM
// (peak) from /proc/self/status, the Go heap from runtime.

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var procStart = time.Now()

func processStatus() map[string]any {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	v := map[string]any{
		"heapMB": m.HeapAlloc >> 20, "sysMB": m.Sys >> 20, "goroutines": runtime.NumGoroutine(),
		"uptimeS": int(time.Since(procStart).Seconds()),
	}
	if f, err := os.Open("/proc/self/status"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, val, ok := strings.Cut(sc.Text(), ":")
			if !ok || (k != "VmRSS" && k != "VmHWM") {
				continue
			}
			kb, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(val), " kB"))
			v[map[string]string{"VmRSS": "rssMB", "VmHWM": "peakRssMB"}[k]] = kb >> 10
		}
	}
	return v
}
