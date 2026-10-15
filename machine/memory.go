package main

// Memory: the machine's own RAM report for the router's starvation watch (router/memory.go; Jarvis 1 read the
// same numbers by Fly exec: lib/memory.js REG_SECTION), and the "free" command that goes before an Upgrade's
// snapshot.
//
// Every memEvery the agent reads /proc (MemTotal, MemAvailable, the kernel's oom_kill count, PSI memory "full"
// avg60, the three biggest processes) and POSTs it to /m/memory. A machine too starved to send it is itself the
// signal: the router counts a silent machine whose last sample was short as starving.
//
// free (router command, an Upgrade only): the session is about to be snapshotted and moved to a bigger machine,
// so its work stops early to give the snapshot the memory: the harness (the machine's main process, whose exit
// stops the Fly machine) is SIGSTOPped, and every other process of this user except the agent is SIGKILLed (Jarvis
// 1's FREEZE_CMD; Deyao, 2026-10-10: kill the AI too, or it starts the build again). The list of what was killed
// goes to ~/artifacts/jarvis2-upgrade-freed.txt, inside the snapshot, for the next machine's "upgraded" message.

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const memEvery = 10 * time.Second

type memProc struct {
	RssKb int64  `json:"rssKb"`
	Comm  string `json:"comm"`
}

type memSample struct {
	TotalKb   int64     `json:"totalKb"`
	AvailKb   int64     `json:"availKb"`
	OOMKills  *int64    `json:"oomKills"`
	PSIFull60 *float64  `json:"psiFull60"`
	Top       []memProc `json:"top"`
	// the root disk ($HOME's filesystem, where the session's work lives): the router warns before it is full
	DiskTotalKb int64 `json:"diskTotalKb,omitempty"`
	DiskAvailKb int64 `json:"diskAvailKb,omitempty"`
}

var procRoot = "/proc"

func readMemory() (memSample, error) {
	var s memSample
	f, err := os.Open(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return s, err
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		switch k {
		case "MemTotal":
			s.TotalKb = n
		case "MemAvailable":
			s.AvailKb = n
		}
	}
	f.Close()
	if s.TotalKb == 0 {
		return s, fmt.Errorf("no MemTotal in meminfo")
	}
	if b, err := os.ReadFile(filepath.Join(procRoot, "vmstat")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "oom_kill "); ok {
				if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					s.OOMKills = &n
				}
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(procRoot, "pressure", "memory")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(l, "full ") {
				continue
			}
			for _, f := range strings.Fields(l) {
				if v, ok := strings.CutPrefix(f, "avg60="); ok {
					if x, err := strconv.ParseFloat(v, 64); err == nil {
						s.PSIFull60 = &x
					}
				}
			}
		}
	}
	s.DiskTotalKb, s.DiskAvailKb = readDisk(diskRoot())
	procs := processes(func(int, int) bool { return true })
	sort.Slice(procs, func(i, j int) bool { return procs[i].rssKb > procs[j].rssKb })
	for i := 0; i < len(procs) && i < 3; i++ {
		s.Top = append(s.Top, memProc{procs[i].rssKb, procs[i].comm})
	}
	return s, nil
}

// diskRoot: the filesystem the session's work lives on
var diskRoot = func() string { h, _ := os.UserHomeDir(); return h }

// readDisk: a filesystem's size and the space an unprivileged user may still write (KiB; 0, 0 when unknown)
func readDisk(path string) (totalKb, availKb int64) {
	var st syscall.Statfs_t
	if path == "" || syscall.Statfs(path, &st) != nil {
		return 0, 0
	}
	return int64(st.Blocks) * st.Bsize / 1024, int64(st.Bavail) * st.Bsize / 1024
}

type proc struct {
	pid, uid int
	rssKb    int64
	comm     string
}

// processes: every process in /proc that keep(pid, uid) accepts, with its resident set and name
func processes(keep func(pid, uid int) bool) []proc {
	ents, _ := os.ReadDir(procRoot)
	var out []proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "status"))
		if err != nil {
			continue
		}
		p := proc{pid: pid, uid: -1}
		for _, l := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(l, ":")
			v = strings.TrimSpace(v)
			switch k {
			case "Name":
				p.comm = v
			case "Uid":
				if f := strings.Fields(v); len(f) > 0 {
					p.uid, _ = strconv.Atoi(f[0])
				}
			case "VmRSS":
				p.rssKb, _ = strconv.ParseInt(strings.TrimSuffix(v, " kB"), 10, 64)
			}
		}
		if keep(pid, p.uid) {
			out = append(out, p)
		}
	}
	return out
}

// memoryReporter: the agent's memory loop (started with the status reports, once booted)
func memoryReporter(c *client) {
	for ; ; time.Sleep(memEvery) {
		s, err := readMemory()
		if err != nil {
			log.Printf("memory: %v", err)
			continue
		}
		if err := c.json("POST", "/m/memory", s, nil); err != nil {
			log.Printf("memory report failed: %v", err)
		}
	}
}

// ---- free (before an Upgrade's snapshot) -------------------------------------------------------------------

var freedFile = "artifacts/jarvis2-upgrade-freed.txt"

// signalProc: the kill(2) the free step uses (a test replaces it)
var signalProc = func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }

// freeMemory: stop the harness (the main process: the agent's parent, which boot exec'd into it), kill every
// other process of this user except the agent itself, and record what was killed. Only on a Fly machine.
func freeMemory() {
	if os.Getenv("FLY_MACHINE_ID") == "" || os.Getuid() == 0 { // never as root: it would kill the whole machine
		return
	}
	freeProcesses(os.Getpid(), os.Getppid(), os.Getuid())
}

func freeProcesses(self, main, uid int) []proc {
	if main > 1 {
		if err := signalProc(main, syscall.SIGSTOP); err != nil {
			log.Printf("free: stopping the harness (%d): %v", main, err)
		}
	}
	victims := processes(func(pid, u int) bool { return u == uid && pid != self && pid != main && pid > 1 })
	sort.Slice(victims, func(i, j int) bool { return victims[i].rssKb > victims[j].rssKb })
	var killed []proc
	for _, p := range victims {
		if signalProc(p.pid, syscall.SIGKILL) == nil {
			killed = append(killed, p)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Jarvis 2 Upgrade, %s: the processes the old machine stopped to free memory for its snapshot (resident memory, name):\n", time.Now().UTC().Format(time.RFC3339))
	for _, p := range killed {
		fmt.Fprintf(&b, "%d MB\t%s\n", p.rssKb/1024, p.comm)
	}
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, freedFile)
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		log.Printf("free: %v", err)
	}
	log.Printf("free: stopped the harness, killed %d processes", len(killed))
	return killed
}
