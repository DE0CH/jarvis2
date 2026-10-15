package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fallbackRouter: the router's /m/fallback/* for one line: m1's snapshot and cert, live copies sent by m2
type fallbackRouter struct {
	certs    map[string]*SignedDoc
	snapshot []byte
	snapSig  string
	live     map[string][3]string // name → body, X-Time, X-Sig
	liveFrom string
}

func (f *fallbackRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch r.URL.Path {
	case "/m/fallback/cert":
		json.NewEncoder(w).Encode(map[string]any{"cert": f.certs[q.Get("machine")]})
	case "/m/fallback/snapshot":
		w.Header().Set("X-Snapshot-Sig", f.snapSig)
		w.Write(f.snapshot)
	case "/m/fallback/transcript":
		l, ok := f.live[q.Get("name")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("X-Live-Machine", f.liveFrom)
		w.Header().Set("X-Live-Time", l[1])
		w.Header().Set("X-Live-Sig", l[2])
		w.Write([]byte(l[0]))
	default:
		w.WriteHeader(404)
	}
}


func TestAFallbackRestoresWhatTheCertNamesFromTheLine(t *testing.T) {
	home, run := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	old := fallbackTmp
	fallbackTmp = filepath.Join(run, "fb.tar.gz")
	defer func() { fallbackTmp = old }()
	core, k1, k2, stranger := newKey(), newKey(), newKey(), newKey()
	lineCert := func(id string, k tkey, line string) *SignedDoc {
		return core.doc(map[string]any{"kind": "succession-cert", "line": line, "machine": map[string]string{"id": id, "signingKey": k.pub()}})
	}
	// m1's snapshot: the workspace and an older copy of the conversation
	snap := tarball(t, ".claude/projects/-home-claude-workspace/conv.jsonl", "line 1\n")
	snapSig, _ := sign(k1.k, []byte(hexSum(string(snap))))
	newer := "line 1\nline 2\nline 3\n"
	liveSig := func(k tkey, body string) string {
		s, _ := sign(k.k, []byte("POST /m/live-transcript 1791700000 "+hexSum(body)))
		return s
	}
	fr := &fallbackRouter{
		certs:    map[string]*SignedDoc{"m1": lineCert("m1", k1, "m1"), "m2": lineCert("m2", k2, "m1"), "mX": lineCert("mX", stranger, "other")},
		snapshot: snap, snapSig: snapSig, liveFrom: "m2",
		live: map[string][3]string{
			"conv.jsonl":   {newer, "1791700000", liveSig(k2, newer)},
			"forged.jsonl": {"evil\n", "1791700000", liveSig(stranger, "evil\n")},
		},
	}
	srv := httptest.NewServer(fr)
	defer srv.Close()
	c := &client{base: srv.URL, me: "m3", sig: newKey().k, http: srv.Client()}
	me := Cert{Kind: "succession-cert", Line: "m1", Machine: &Machine{ID: "m3"}}
	fb := &FallbackRef{Lost: "m2", Machine: "m1", Sha256: hexSum(string(snap)), TakenAt: "2026-10-15T01:00:00Z", Transcripts: []LiveRef{
		{Name: "conv.jsonl", Sha256: hexSum(newer), Size: int64(len(newer))},
		{Name: "forged.jsonl", Sha256: hexSum("evil\n"), Size: 5},
	}}
	if err := restoreFallback(c, core.pub(), me, fb); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(home, ".claude/projects/-home-claude-workspace/conv.jsonl"))
	if string(got) != newer {
		t.Fatalf("the newer live copy wasn't placed: %q", got)
	}
	// the forged copy is signed by no machine of this line (the sender header says m2, the key is a stranger's)
	if found, _ := filepath.Glob(filepath.Join(home, ".claude/projects/*/forged.jsonl")); len(found) != 0 {
		t.Fatal("a copy not signed by the line was placed")
	}
	rep, _ := os.ReadFile(filepath.Join(home, fallbackFile))
	if !strings.Contains(string(rep), "m2") || !strings.Contains(string(rep), "1 of 2") {
		t.Fatalf("report %q", rep)
	}

	// a snapshot other than the one the cert names, or from another line, stops the boot
	bad := *fb
	bad.Sha256 = strings.Repeat("0", 64)
	if err := restoreFallback(c, core.pub(), me, &bad); err == nil {
		t.Fatal("restored a snapshot the cert doesn't name")
	}
	bad = *fb
	bad.Machine = "mX"
	if err := restoreFallback(c, core.pub(), me, &bad); err == nil || !strings.Contains(err.Error(), "not this line") {
		t.Fatalf("restored another line's snapshot: %v", err)
	}
	// signed by another key: refused
	fr.snapSig, _ = sign(stranger.k, []byte(hexSum(string(snap))))
	if err := restoreFallback(c, core.pub(), me, fb); err == nil {
		t.Fatal("restored a snapshot not signed by its machine")
	}
}

func TestTheCertsFallbackIsReadStrictly(t *testing.T) {
	ok := `{"fallback":{"lost":"m2","machine":"m1","sha256":"` + strings.Repeat("a", 64) + `","transcripts":[{"name":"c.jsonl","sha256":"` + strings.Repeat("b", 64) + `","size":3}]}}`
	if v, err := vouch(v2("", ok)); err != nil || v.Once.Fallback == nil || v.Once.Fallback.Machine != "m1" {
		t.Fatalf("%+v %v", v.Once, err)
	}
	for _, bad := range []string{
		`{"fallback":{"lost":"m2","machine":"m1","sha256":"x"}}`,
		`{"fallback":{"lost":"../m2"}}`,
		`{"fallback":{"lost":"m2","transcripts":[{"name":"../../.bashrc","sha256":"` + strings.Repeat("b", 64) + `","size":3}]}}`,
		`{"fallback":{"lost":"m2","extra":1}}`,
	} {
		if _, err := vouch(v2("", bad)); err == nil {
			t.Errorf("took %s", bad)
		}
	}
}

func TestTheMemoryReportCarriesTheDisk(t *testing.T) {
	total, avail := readDisk(t.TempDir())
	if total <= 0 || avail < 0 || avail > total {
		t.Fatalf("disk %d / %d", avail, total)
	}
	b, _ := json.Marshal(memSample{TotalKb: 1, DiskTotalKb: total, DiskAvailKb: avail})
	if !bytes.Contains(b, []byte(`"diskTotalKb"`)) {
		t.Fatal(string(b))
	}
}
