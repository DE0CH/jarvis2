package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

// davFake: just enough WebDAV (MKCOL, PUT, GET, HEAD, DELETE, PROPFIND depth 1) in memory
type davFake struct {
	mu    sync.Mutex
	files map[string][]byte
	puts  int
}

func (d *davFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := strings.TrimSuffix(r.URL.Path, "/")
	switch r.Method {
	case "MKCOL":
		w.WriteHeader(201)
	case "PUT":
		b, _ := io.ReadAll(r.Body)
		d.files[p] = b
		d.puts++
		w.WriteHeader(201)
	case "GET", "HEAD":
		b, ok := d.files[p]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(b)
	case "DELETE":
		delete(d.files, p)
		w.WriteHeader(204)
	case "PROPFIND":
		var names []string
		for k := range d.files {
			if strings.HasPrefix(k, p+"/") && !strings.Contains(strings.TrimPrefix(k, p+"/"), "/") {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		w.WriteHeader(207)
		fmt.Fprintf(w, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>%s/</d:href></d:response>`, p)
		for _, n := range names {
			fmt.Fprintf(w, `<d:response><d:href>%s</d:href></d:response>`, n)
		}
		fmt.Fprint(w, `</d:multistatus>`)
	}
}

func TestStateBackupAndRestore(t *testing.T) {
	dav := &davFake{files: map[string][]byte{}}
	srv := httptest.NewServer(dav)
	defer srv.Close()
	box := newStorageBox(srv.URL, "u", "p")
	id, _ := age.GenerateX25519Identity()

	dir := t.TempDir()
	writeData(t, dir, "state.json", `{"sessions":{}}`)
	writeData(t, dir, "input-log.jsonl", "a\n")
	writeData(t, dir, "snapshots/m1.tar.gz", "SNAP1")
	writeData(t, dir, "snapshots/m1.carry", "CARRY")
	writeData(t, dir, "tmp/x", "no")
	writeData(t, dir, "router.leader", "")

	backupMu.Lock()
	backupFP = ""
	info, err := backupData(dir, box, id.Recipient(), time.Date(2026, 10, 15, 6, 0, 0, 0, time.UTC))
	backupMu.Unlock()
	if err != nil || info == nil || info.Snaps != 1 || info.Size == 0 {
		t.Fatalf("first backup: %+v %v", info, err)
	}
	for k, v := range dav.files {
		if strings.Contains(string(v), "CARRY") || strings.Contains(string(v), "SNAP1") {
			t.Fatalf("%s holds plaintext", k)
		}
	}
	// nothing changed: nothing sent
	puts := dav.puts
	backupMu.Lock()
	info, err = backupData(dir, box, id.Recipient(), time.Date(2026, 10, 15, 6, 15, 0, 0, time.UTC))
	backupMu.Unlock()
	if err != nil || info != nil || dav.puts != puts {
		t.Fatalf("unchanged: %+v %v puts %d→%d", info, err, puts, dav.puts)
	}
	// a change: a new state; a deleted snapshot goes from the box too
	writeData(t, dir, "input-log.jsonl", "a\nb\n")
	os.Remove(filepath.Join(dir, "snapshots", "m1.tar.gz"))
	writeData(t, dir, "snapshots/m2.tar.gz", "SNAP2")
	backupMu.Lock()
	info, err = backupData(dir, box, id.Recipient(), time.Date(2026, 10, 15, 6, 30, 0, 0, time.UTC))
	backupMu.Unlock()
	if err != nil || info == nil || !strings.HasSuffix(info.Path, "state-20261015T063000Z.tar.gz.age") {
		t.Fatalf("second backup: %+v %v", info, err)
	}
	if _, ok := dav.files["/"+backupSnapsDir+"/m1.tar.gz.age"]; ok {
		t.Fatal("a snapshot gone here must go from the box")
	}

	// a rebuilt box
	out := t.TempDir()
	if err := restoreFromBackup(out, box, id.String()); err != nil {
		t.Fatal(err)
	}
	if readData(t, out, "input-log.jsonl") != "a\nb\n" || readData(t, out, "snapshots/m1.carry") != "CARRY" ||
		readData(t, out, "snapshots/m2.tar.gz") != "SNAP2" || readData(t, out, "state.json") != `{"sessions":{}}` {
		t.Fatal("restore incomplete")
	}
	for _, no := range []string{"tmp/x", "router.leader", "snapshots/m1.tar.gz"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(no))); err == nil {
			t.Fatalf("%s restored", no)
		}
	}
	// the wrong key opens nothing
	other, _ := age.GenerateX25519Identity()
	if err := restoreFromBackup(t.TempDir(), box, other.String()); err == nil {
		t.Fatal("another key must not open the backup")
	}
}

func TestStateBackupKeepsNewest48(t *testing.T) {
	dav := &davFake{files: map[string][]byte{}}
	srv := httptest.NewServer(dav)
	defer srv.Close()
	box := newStorageBox(srv.URL, "u", "p")
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 52; i++ {
		writeData(t, dir, "state.json", fmt.Sprint(i))
		backupMu.Lock()
		if _, err := backupData(dir, box, id.Recipient(), at.Add(time.Duration(i)*time.Minute)); err != nil {
			backupMu.Unlock()
			t.Fatal(err)
		}
		backupMu.Unlock()
	}
	n := 0
	for k := range dav.files {
		if strings.Contains(k, "/state-") {
			n++
		}
	}
	if n != backupKeep {
		t.Fatalf("%d state backups kept, want %d", n, backupKeep)
	}
	if _, ok := dav.files["/"+backupDir+"/state-20261015T000000Z.tar.gz.age"]; ok {
		t.Fatal("the oldest must go")
	}
}
