package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// A session proposing a new session attaches files it staged itself: they go into the new line's signed config by
// hash exactly as the app's do, the app reads them back for the approval page, and the new session's first machine
// lists them with the core's attestation. An upload is its owner's only: another session (or the app) can't add to
// it or bind it; a batch can't bind one upload twice.
func TestASessionsProposalCarriesItsOwnUploads(t *testing.T) {
	rg, vc := v2Rig(t)
	r := rg.r
	r.cfg.NoAccess = true
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	ma, mb := newTestMachine(r, "mA"), newTestMachine(r, "mB")
	mh := r.MachineHandler()

	photo, notes := "\x89PNG a screenshot", "some notes"
	code, out := ma.do(t, mh, "PUT", "/m/api/sessions/sA/uploads/u1/screen%20shot.png", photo)
	if code != 200 || out["name"] != "screen_shot.png" || out["isImage"] != true || out["size"] != float64(len(photo)) {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := ma.do(t, mh, "PUT", "/m/api/sessions/sA/uploads/u1/notes.txt", notes); code != 200 || out["isImage"] != false {
		t.Fatalf("%d %v", code, out)
	}
	// another session's path, another session's upload, the app on a session's upload
	if code, _ := ma.do(t, mh, "PUT", "/m/api/sessions/sB/uploads/u2/x.txt", "x"); code != 403 {
		t.Fatalf("another session's path: %d", code)
	}
	if code, _ := mb.do(t, mh, "PUT", "/m/api/sessions/sB/uploads/u1/x.txt", "x"); code != 400 {
		t.Fatalf("another session's upload: %d", code)
	}
	if code, _ := appDo(t, r, "POST", "/api/uploads", "x", "x-upload-id", "u1", "x-upload-name", "x.txt"); code != 400 {
		t.Fatalf("the app on a session's upload: %d", code)
	}
	// another session can't bind it, and neither can the app
	if code, out := mb.do(t, mh, "POST", "/m/api/sessions", `{"prompt":"p","explanation":"e","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}}`); code != 400 {
		t.Fatalf("another session bound it: %d %v", code, out)
	}
	if code, out := appDo(t, r, "POST", "/api/sessions", `{"prompt":"p","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}}`); code != 400 {
		t.Fatalf("the app bound it: %d %v", code, out)
	}
	// a file it never uploaded
	if code, _ := ma.do(t, mh, "POST", "/m/api/sessions", `{"prompt":"p","explanation":"e","attachments":{"uploadId":"u1","files":[{"name":"other.png"}]}}`); code != 400 {
		t.Fatalf("a file never uploaded: %d", code)
	}
	// a batch binding one upload twice: nothing filed
	two := `{"summary":"s","items":[{"intent":"new-session","requestId":"a","prompt":"p","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}},` +
		`{"intent":"new-session","requestId":"b","prompt":"p","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}}]}`
	if code, out := ma.do(t, mh, "POST", "/m/api/requests/batch", two); code != 400 || len(r.Inbox()) != 0 {
		t.Fatalf("one upload twice: %d %v", code, out)
	}

	body := `{"requestId":"r1","label":"look","prompt":"what is on the screen?","harness":"claude","explanation":"Deyao asked",
		"attachments":{"uploadId":"u1","files":[{"name":"screen shot.png"},{"name":"notes.txt"}]}}`
	code, out = ma.do(t, mh, "POST", "/m/api/sessions", body)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	sid := out["id"].(string)
	if code, out := ma.do(t, mh, "POST", "/m/api/sessions", body); code != 200 || out["id"] != sid {
		t.Fatalf("a repeat: %d %v", code, out)
	}
	waitFor(t, "succession", func() bool { return vc.last("/succession") != nil })
	var c SessionConfig
	json.Unmarshal([]byte(vc.last("/succession")["options"].(map[string]any)["config"].(string)), &c)
	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	if len(c.Attachments) != 2 || c.Attachments[0] != (AttachmentRef{Name: "screen_shot.png", Sha256: hash(photo), Size: int64(len(photo))}) ||
		c.Attachments[1] != (AttachmentRef{Name: "notes.txt", Sha256: hash(notes), Size: int64(len(notes))}) {
		t.Fatalf("signed config %+v", c)
	}
	waitFor(t, "approval", func() bool {
		ok := false
		r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				ok = ok || (a.Session == sid && a.Options["attachments"] == "2 file(s)" && a.Origin != nil &&
					a.Origin.Caller == (Caller{Kind: "session", Session: "sA"}) && len(a.Origin.Call.Args["attachments"].([]string)) == 2)
			}
		})
		return ok
	})
	// once bound, the upload takes no more files
	if code, _ := ma.do(t, mh, "PUT", "/m/api/sessions/sA/uploads/u1/late.txt", "late"); code != 400 {
		t.Fatalf("a file added after the proposal: %d", code)
	}
	// the app reads it back for the approval page
	if w := appGet(r, "/api/sessions/"+sid+"/attachments/screen_shot.png"); w.Code != 200 || w.Body.String() != photo {
		t.Fatalf("app read: %d %q", w.Code, w.Body.String())
	}
	// the new session's first machine lists both, attested
	r.st.Do(func(d *persisted) {
		d.Sessions[sid].MachineID, d.Sessions[sid].State = "mN", "initialising"
		d.Machines["mN"] = sid
	})
	mn := newTestMachine(r, "mN")
	code, out = mn.do(t, mh, "GET", "/m/attachments", "")
	if code != 200 || len(out["files"].([]any)) != 2 || len(out["attest"].(map[string]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}
}

// a session holds at most maxSessionUploads unbound uploads; unbound ones go with their owner
func TestASessionsUnboundUploadsAreCapped(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()
	for i := 0; i < maxSessionUploads; i++ {
		if code, out := m.do(t, h, "PUT", "/m/api/sessions/sA/uploads/u"+string(rune('a'+i))+"/f.txt", "x"); code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	if code, _ := m.do(t, h, "PUT", "/m/api/sessions/sA/uploads/uz/f.txt", "x"); code != 400 {
		t.Fatalf("one upload too many: %d", code)
	}
	if code, _ := m.do(t, h, "PUT", "/m/api/sessions/sA/uploads/ua/g.txt", "y"); code != 200 {
		t.Fatalf("another file in an upload it holds: %d", code)
	}
	r.st.Do(func(d *persisted) { delete(d.Sessions, "sA") })
	r.sweepUploads(time.Now())
	n := 0
	r.st.Do(func(d *persisted) { n = len(uploads(d)) })
	if n != 0 {
		t.Fatalf("%d uploads left after their owner went", n)
	}
}

func appGet(r *Router, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", target, nil))
	return w
}
