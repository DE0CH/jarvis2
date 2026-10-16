package main

// Disk: the machine's own disk report (router/disk.go), every diskEvery: the root filesystem and, on a machine
// with a volume (volume.go), the volume at /data that holds the session's state.

import (
	"log"
	"syscall"
	"time"
)

const diskEvery = 30 * time.Second

type diskFS struct {
	TotalKb int64 `json:"totalKb"`
	AvailKb int64 `json:"availKb"`
}

type diskSample struct {
	Root *diskFS `json:"root"`
	Data *diskFS `json:"data,omitempty"`
}

var statfs = syscall.Statfs

func readFS(path string) (*diskFS, error) {
	var st syscall.Statfs_t
	if err := statfs(path, &st); err != nil {
		return nil, err
	}
	bs := int64(st.Bsize)
	return &diskFS{TotalKb: int64(st.Blocks) * bs / 1024, AvailKb: int64(st.Bavail) * bs / 1024}, nil
}

func readDisk() (diskSample, error) {
	root, err := readFS("/")
	if err != nil {
		return diskSample{}, err
	}
	s := diskSample{Root: root}
	if hasVolume() {
		if d, err := readFS(volumeRoot); err == nil {
			s.Data = d
		}
	}
	return s, nil
}

// diskReporter: the supervisor's disk report (started with the status reports, once booted)
func diskReporter(c *client) {
	for ; ; time.Sleep(diskEvery) {
		s, err := readDisk()
		if err != nil {
			log.Printf("disk: %v", err)
			continue
		}
		if err := c.json("POST", "/m/disk", s, nil); err != nil {
			log.Printf("disk report failed: %v", err)
		}
	}
}
