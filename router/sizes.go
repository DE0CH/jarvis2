package main

import (
	"fmt"
	"strconv"
	"strings"
)

// ---- machine sizes (the same block is in router/sizes.go, core/fly.go and machine/deliver.go; TestSizeBlocksMatch) ----

// The sizes: small (2 GB), medium (4 GB), large (8 GB), then every doubling past large, named by its memory ("16gb",
// "32gb", …). Upgrade moves a session one step up, and there is no last step: a guest Fly can't make is Fly's to
// refuse, with its own error.
var namedSizes = map[string]int{"small": 2, "medium": 4, "large": 8}

// sizeMemGB: the size's memory in GB; 0 = not a size (the 1<<20 bound only keeps memory_mb an ordinary int)
func sizeMemGB(size string) int {
	if gb := namedSizes[size]; gb != 0 {
		return gb
	}
	n, err := strconv.Atoi(strings.TrimSuffix(size, "gb"))
	if err != nil || n < 16 || n > 1<<20 || n&(n-1) != 0 || strconv.Itoa(n)+"gb" != size {
		return 0
	}
	return n
}

// sizeGuest: the size's Fly guest. Fly takes at most 2 GB per shared CPU and 8 GB per performance CPU
// (fly.io/docs/machines/guides-examples/machine-sizing). The named three have one shared CPU per GB; 16 GB is the
// most a shared guest holds (8 CPUs × 2 GB); past it the guest is performance, with large's 8 CPUs or, once the
// memory needs more (8 GB each), memory/8 CPUs.
func sizeGuest(size string) (cpuKind string, cpus, memoryMB int) {
	gb := sizeMemGB(size)
	switch {
	case gb == 0:
		return "", 0, 0
	case gb <= 8:
		return "shared", gb, gb * 1024
	case gb <= 16:
		return "shared", 8, gb * 1024
	}
	return "performance", max(8, gb/8), gb * 1024
}

// nextSize: the size Upgrade moves to, twice the memory (a session with no size runs medium)
func nextSize(size string) string {
	gb := sizeMemGB(size)
	if gb == 0 {
		gb = namedSizes["medium"]
	}
	for name, n := range namedSizes {
		if n == 2*gb {
			return name
		}
	}
	return strconv.Itoa(2*gb) + "gb"
}

// sizeText: "large (8 GB)", "16 GB"
func sizeText(size string) string {
	if gb := namedSizes[size]; gb != 0 {
		return fmt.Sprintf("%s (%d GB)", size, gb)
	}
	return fmt.Sprintf("%d GB", sizeMemGB(size))
}

// ---- end of the machine sizes block ----

// sizeLabel: the size's guest as the apps show it, "8×shared · 16 GB" ("" = not a size)
func sizeLabel(size string) string {
	kind, cpus, mb := sizeGuest(size)
	if kind == "" {
		return ""
	}
	return fmt.Sprintf("%d×%s · %d GB", cpus, kind, mb/1024)
}
