package notary

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

var sub = strings.Repeat("ab", 32)

func TestChallengesFormAHashChainOnTheNotarysClock(t *testing.T) {
	s, _ := kernel.NewSigner()
	var log bytes.Buffer
	n := New(s, &log)
	at := time.Date(2026, 10, 14, 12, 0, 0, 5, time.UTC)
	n.SetClock(func() time.Time { return at })
	r := kernel.Roster{Notary: s.PublicKey()}
	prev := ""
	for i := 0; i < 3; i++ {
		d, err := n.Challenge(sub, "succession")
		if err != nil {
			t.Fatal(err)
		}
		c, err := kernel.OpenChallenge(r, d)
		if err != nil {
			t.Fatal(err)
		}
		if c.Seq != int64(i) || c.Prev != prev || c.At != "2026-10-14T12:00:00.000000005Z" || c.Subject != sub || c.About != "succession" || len(c.Nonce) != 32 {
			t.Fatalf("entry %d: %+v", i, c)
		}
		prev = d.ID()
	}
	// every challenge is in the log, one signed document per line
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d log lines", len(lines))
	}
	var last kernel.SignedDoc
	json.Unmarshal([]byte(lines[2]), &last)
	if last.ID() != prev {
		t.Fatal("the log's last line is the last challenge")
	}
}

// Forbidden: a subject that isn't a lower-case hex sha256, an about that isn't a word
func TestNotaryRefusesBadInput(t *testing.T) {
	s, _ := kernel.NewSigner()
	n := New(s, nil)
	for _, c := range [][2]string{{"ab", "x"}, {strings.ToUpper(sub), "x"}, {sub, ""}, {sub, "Not a word"}, {sub + "00", "x"}, {strings.Repeat("zz", 32), "x"}} {
		if _, err := n.Challenge(c[0], c[1]); err == nil {
			t.Fatalf("%q/%q accepted", c[0], c[1])
		}
	}
}

type badWriter struct{}

func (badWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// A challenge that can't be logged isn't issued, and the chain doesn't move
func TestNotLoggedIsNotIssued(t *testing.T) {
	s, _ := kernel.NewSigner()
	n := New(s, badWriter{})
	if _, err := n.Challenge(sub, "x"); err == nil {
		t.Fatal("issued without a log")
	}
	if n.seq != 0 || n.head != "" {
		t.Fatal("the chain moved")
	}
}

func TestNotaryRoute(t *testing.T) {
	s, _ := kernel.NewSigner()
	n := New(s, nil)
	r := n.Routes()["POST /challenge"]
	out, err := r([]byte(`{"subject":"` + sub + `","about":"command"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kernel.OpenChallenge(kernel.Roster{Notary: s.PublicKey()}, out.(kernel.SignedDoc)); err != nil {
		t.Fatal(err)
	}
	if _, err := r([]byte(`{"subject":"` + sub + `","about":"x","seq":5}`)); err == nil {
		t.Fatal("a caller-chosen field accepted")
	}
}
