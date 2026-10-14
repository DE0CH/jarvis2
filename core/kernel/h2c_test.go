package kernel

import (
	"crypto/ecdh"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The points match testdata/h2c.json, which testdata/h2c.py (an independent implementation) wrote
func TestHashToCurveMatchesThePythonVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/h2c.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) < 5 {
		t.Fatal("too few vectors")
	}
	for name, key := range want {
		if got := HashToKey(name); got != key {
			t.Fatalf("%q: %s, python says %s", name, got, key)
		}
	}
}

// And python itself, when present (the image build has none; the golden file covers it there)
func TestHashToCurveAgainstPythonLive(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	names := []string{SinkKeyName(UseEncryption), SourceKeyName("source-abcdefabcdefabcdefabcdefabcdefab", UseEncryption), "x"}
	out, err := exec.Command(py, append([]string{"testdata/h2c.py"}, names...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(out))
	for i, n := range names {
		if got[i] != HashToKey(n) {
			t.Fatalf("%q: go %s, python %s", n, HashToKey(n), got[i])
		}
	}
}

func TestHashedPointsAreOnTheCurveWithEvenY(t *testing.T) {
	for _, n := range []string{"a", "b", SinkKeyName(UseSigning), SourceKeyName("source-00000000000000000000000000000001", UseEncryption)} {
		p := HashToPoint(n)
		if _, err := ecdh.P256().NewPublicKey(p); err != nil {
			t.Fatalf("%q: %v", n, err)
		}
		if p[64]&1 != 0 {
			t.Fatalf("%q: odd y", n)
		}
	}
	if HashToKey(SinkKeyName(UseSigning)) == HashToKey(SinkKeyName(UseEncryption)) {
		t.Fatal("signing and encryption keys differ")
	}
}

// A source's and the sink's keys are the hashed ones; a machine's are its own
func TestObjectKeys(t *testing.T) {
	sink := Object{ID: Sink}
	if sink.EncryptionKeyOf() != HashToKey("jarvis2 sink encryption") || sink.SigningKeyOf() != HashToKey("jarvis2 sink signing") {
		t.Fatal("sink keys")
	}
	src := Object{ID: "source-0123456789abcdef0123456789abcdef"}
	if src.EncryptionKeyOf() != HashToKey("jarvis2 source-0123456789abcdef0123456789abcdef encryption") {
		t.Fatal("source key")
	}
	m := Object{ID: "e286", SigningKey: "S", EncryptionKey: "E"}
	if m.EncryptionKeyOf() != "E" || m.SigningKeyOf() != "S" {
		t.Fatal("machine keys")
	}
}
