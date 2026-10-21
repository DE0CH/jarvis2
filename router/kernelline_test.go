package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/kernel/doc"
	"github.com/DE0CH/jarvis2/kernel/gv"
	"github.com/DE0CH/jarvis2/kernel/kerneltest"
	"github.com/DE0CH/jarvis2/kernel/sig"
)

const kernelImage = "ghcr.io/de0ch/jarvis2-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// kernelRig: the archive rig with the real kernel beside the fake core, its root grant in, new sessions on it
func kernelRig(t *testing.T) (*rig, *kerneltest.Kernel) {
	rg := newRig(t)
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	rg.r.kernel = &KernelClient{url: k.URLFor, http: http.DefaultClient, ids: map[string]sig.Identity{}}
	rg.r.cfg.SessionImage, rg.r.cfg.Region = kernelImage, "lhr"
	rg.r.policy.Harnesses["claude"] = HarnessPolicy{}
	rg.r.st.Do(func(d *persisted) { d.KernelRoot = &gv.Signed{Grant: k.RootTop(), By: "root"} })
	return rg, k
}

// kdo: a request signed by a kernel machine's key, as the supervisor signs it (machine/main.go client.raw)
func kdo(t *testing.T, h http.Handler, m *kerneltest.FakeMachine, method, path, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256([]byte(body))
	s, _ := m.Sig.Sign([]byte(method + " " + path + " " + ts + " " + hex.EncodeToString(sum[:])))
	req.Header.Set("X-Machine", m.ID)
	req.Header.Set("X-Time", ts)
	req.Header.Set("X-Sig", s)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func kernelSession(rg *rig, sid string) Session {
	var s Session
	rg.r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
		}
	})
	return s
}

// a kernel line's life through the router and the real kernel: the phone signs the source, a machine is spawned and
// reads its boot documents, pulls its secrets, pauses into a source holding its snapshot, resumes from it (the new
// machine restores the old one's snapshot), and the destroy archives it and burns its source
func TestAKernelLinesLife(t *testing.T) {
	rg, k := kernelRig(t)
	sid, err := rg.r.CreateSession(NewSession{Label: "on the kernel", Harness: "claude", PermissionMode: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "the approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			for _, x := range d.Approvals {
				if x.Session == sid {
					a = x
				}
			}
		})
		return a != nil
	})
	if a.Kind != kernelApprovalKind {
		t.Fatalf("approval %s", a.Kind)
	}
	var c doc.Cert
	if err := json.Unmarshal([]byte(a.Challenge.Payload), &c); err != nil || c.Pred != doc.Sink || c.Source.Image != kernelImage {
		t.Fatal(err, c)
	}
	var settings struct {
		Harness, PermissionMode string
	}
	json.Unmarshal(c.Source.Settings, &settings)
	if settings.Harness != "claude" || settings.PermissionMode != "auto" || c.Pair.Conditions[0] != "session:"+sid {
		t.Fatalf("%s %+v", c.Source.Settings, c.Pair)
	}
	signature, _ := k.Phone.Sign([]byte(a.Challenge.Payload))
	if _, _, err := rg.r.Respond(a.ID, signature); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the machine", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.Kernel.MachineCert != nil })
	s := kernelSession(rg, sid)
	m1 := k.Fly.Machine(s.MachineID)
	h := rg.r.MachineHandler()
	code, body := kdo(t, h, m1, "GET", "/m/kernel/boot", "")
	var boot struct {
		Grant gv.Signed `json:"grant"`
	}
	if code != 200 || json.Unmarshal(body, &boot) != nil {
		t.Fatal(code, string(body))
	}
	g, err := gv.Open(boot.Grant, k.Box.PublicKey())
	if err != nil || g.Machine != doc.Object("fly-"+m1.ID) || g.Keys.SigningKey != m1.Sig.PublicKey() {
		t.Fatal(err, g)
	}
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 || !strings.Contains(string(body), "secrets") {
		t.Fatal(code, string(body))
	}
	if st := kernelSession(rg, sid).State; st != "started" {
		t.Fatalf("state %s", st)
	}
	// pause: the machine's signed snapshot is here; the spawner kills it into a source holding its hash
	tarball := makeTar(t, rg.files)
	sum := sha256.Sum256(tarball)
	snapSig, _ := m1.Sig.Sign([]byte(hex.EncodeToString(sum[:])))
	p := rg.r.st.snapshotPath(m1.ID)
	os.WriteFile(p, tarball, 0o600)
	os.WriteFile(p+".sig", []byte(snapSig), 0o600)
	if err := rg.r.Pause(sid); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitActionEnd(sid, "paused"); err != nil {
		t.Fatal(err, kernelSession(rg, sid).Error)
	}
	s = kernelSession(rg, sid)
	sc, _ := doc.PeekCert(*s.Kernel.SourceCert)
	if sc.Pred != doc.Object("fly-"+m1.ID) || sc.Source.Snapshot != hex.EncodeToString(sum[:]) || s.Kernel.Grant == nil || s.NoSnapshot != "" {
		t.Fatalf("%+v %q", sc, s.NoSnapshot)
	}
	if m1.State != "destroyed" {
		t.Fatal("the old machine is still there")
	}
	// resume: a new machine from that source restores m1's snapshot
	if err := rg.r.Resume(sid, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the second machine", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.MachineID != m1.ID && s.Kernel.MachineCert != nil })
	m2 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
	code, body = kdo(t, h, m2, "GET", "/m/snapshot", "")
	if code != 200 || string(body) != string(tarball) {
		t.Fatalf("the predecessor's snapshot: %d", code)
	}
	// ✱ the first machine is gone: its calls are refused
	if code, _ := kdo(t, h, m1, "GET", "/m/kernel/boot", ""); code == 200 {
		t.Fatal("a killed machine read the line's documents")
	}
	// destroy: archived, the source burned (a second spawn from it would be refused by the notarizer)
	if err := rg.r.Destroy(sid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool {
		gone := false
		rg.r.st.Do(func(d *persisted) { gone = d.Sessions[sid] == nil })
		return gone
	})
}

// ✱ without the root grant, new sessions stay on the old core
func TestNoKernelRootNoKernelSessions(t *testing.T) {
	rg, _ := kernelRig(t)
	rg.r.st.Do(func(d *persisted) { d.KernelRoot = nil })
	sid, err := rg.r.CreateSession(NewSession{Label: "x", Harness: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	if kernelSession(rg, sid).Kernel != nil {
		t.Fatal("a kernel line without the root's grant")
	}
}
