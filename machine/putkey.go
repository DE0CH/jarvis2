package main

// Writing one key into a store from a session (Deyao, 2026-10-13: any session may write a key, with no approval: it
// can't read the store, and the key's backup keeps every earlier value; DESIGN "Layers": writing secrets is protected
// only by the router). The value never leaves this machine in the clear. It goes three ways, each sealed here:
//
//   - to the store key P + K (phone + secrets: only both together open it), under a fresh data key (core/kernel/secrets
//     keys.go);
//   - to the master key, for its backup (only Deyao's kit opens it);
//   - to secrets' own agreement key K ("live"), so secrets serves it on the next pull of a store that is unlocked.
//
// The store key, the master key and the phone come from secrets' signed documents (checked against secrets' key in the
// roster), and K is checked against them (P + K must be the signed store key), so the router can't hand this machine a
// key of its own.
//
//	jarvis2 put-key STORE KEY [--explain TEXT] < value     the value from stdin (never an argument)
//	jarvis2 delete-key STORE KEY
//
// Every running session whose grant names the store (this one too) gets the new value with its next pull: the router
// sends them "pull".

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// writerText: secrets.WriterText (what a setup writer signs; recorded the same way for every write)
func writerText(store, key, e, data, backupSha string) string {
	sum := ""
	if data != "" {
		sum = kernel.SHA256Hex(data)
	}
	return "jarvis2-store-key\n" + store + "\n" + key + "\n" + e + "\n" + sum + "\n" + backupSha
}

// sealTargets: the answer of GET /m/store-keys, checked
type sealTargets struct {
	StoreKey  string // P + K
	Master    string
	Agreement string // K
}

// addPoints: a + b on P-256, uncompressed, base64 ("" when either isn't a point)
func addPoints(a, b string) string {
	pa, err1 := kernel.ParsePoint(a)
	pb, err2 := kernel.ParsePoint(b)
	if err1 != nil || err2 != nil {
		return ""
	}
	c := elliptic.P256()
	x1, y1 := elliptic.Unmarshal(c, pa.Bytes()) //nolint:staticcheck // plain point addition, public points only
	x2, y2 := elliptic.Unmarshal(c, pb.Bytes()) //nolint:staticcheck
	if x1 == nil || x2 == nil {
		return ""
	}
	x, y := c.Add(x1, y1, x2, y2)                               //nolint:staticcheck
	return kernel.B64.EncodeToString(elliptic.Marshal(c, x, y)) //nolint:staticcheck
}

// checkSealTargets: secrets' state (master key, phone) and store key, signed by secrets' key, and K with P + K = the
// store key
func checkSealTargets(r kernel.Roster, state, storeKey kernel.SignedDoc, agreement string) (sealTargets, error) {
	var st struct {
		Kind   string `json:"kind"`
		Master string `json:"master"`
		Phone  *struct {
			SigningKey   string `json:"signingKey"`
			AgreementKey string `json:"agreementKey"`
		} `json:"phone"`
		Bundle string `json:"bundle"`
	}
	if kernel.Open(r.Secrets, state, &st) != nil || st.Kind != "secrets-state" || st.Master == "" || st.Phone == nil {
		return sealTargets{}, errors.New("secrets' state isn't signed by secrets' key, or secrets isn't set up")
	}
	var sk struct {
		Kind     string `json:"kind"`
		Phone    string `json:"phone"`
		StoreKey string `json:"storeKey"`
	}
	if kernel.Open(r.Secrets, storeKey, &sk) != nil || sk.Kind != "store-key" || sk.Phone != st.Phone.AgreementKey || sk.StoreKey == "" {
		return sealTargets{}, errors.New("the store key isn't secrets' for its phone")
	}
	if addPoints(st.Phone.AgreementKey, agreement) != sk.StoreKey {
		return sealTargets{}, errors.New("secrets' agreement key doesn't make the signed store key with the phone's")
	}
	return sealTargets{StoreKey: sk.StoreKey, Master: st.Master, Agreement: agreement}, nil
}

// keyWriteRequest: what the router takes (docs/API-grants.md POST /m/stores/{store}/keys/{key}), sealed here
func keyWriteRequest(t sealTargets, store, key string, value []byte, del bool, explanation string) (map[string]any, error) {
	req := map[string]any{"delete": del, "explanation": explanation}
	if del {
		return req, nil
	}
	dk := make([]byte, 32)
	rand.Read(dk)
	wrapped, err := kernel.SealTo(t.StoreKey, dk, "jarvis2/store-data-key")
	if err != nil {
		return nil, fmt.Errorf("the store key: %w", err)
	}
	data := kernel.B64.EncodeToString(kernel.GCMSeal(dk, value, []byte(store+"\n"+key)))
	backup, err := sealWithAAD(t.Master, value, "jarvis2/backup", []byte(store+"\n"+key))
	if err != nil {
		return nil, fmt.Errorf("the master key: %w", err)
	}
	h := sha256.Sum256([]byte(backup.E + "\n" + backup.Data))
	backupSha := hex.EncodeToString(h[:])
	live, err := kernel.SealTo(t.Agreement, value, "jarvis2/live-key\n"+store+"\n"+key)
	if err != nil {
		return nil, fmt.Errorf("secrets' agreement key: %w", err)
	}
	req["wrapped"] = map[string]string{"e": wrapped.E, "wrapped": wrapped.Data}
	req["data"], req["live"], req["backup"], req["backupSha256"] = data, live, backup, backupSha
	req["writerText"] = writerText(store, key, wrapped.E, data, backupSha)
	return req, nil
}

// sealWithAAD: kernel.SealTo with associated data (the backup's format: store\nkey bound in)
func sealWithAAD(recipient string, plain []byte, info string, aad []byte) (kernel.Sealed, error) {
	r, err := kernel.ParsePoint(recipient)
	if err != nil {
		return kernel.Sealed{}, err
	}
	e, err := r.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return kernel.Sealed{}, err
	}
	x, err := e.ECDH(r)
	if err != nil {
		return kernel.Sealed{}, err
	}
	return kernel.Sealed{E: kernel.B64.EncodeToString(e.PublicKey().Bytes()), Data: kernel.B64.EncodeToString(kernel.GCMSeal(kernel.KDF(x, info), plain, aad))}, nil
}

// putKeyCmd: jarvis2 put-key STORE KEY [--explain TEXT] (value on stdin) | jarvis2 delete-key STORE KEY
func putKeyCmd(args []string, del bool) error {
	usage := "usage: jarvis2 put-key STORE KEY [--explain TEXT] < value   |   jarvis2 delete-key STORE KEY"
	explain := ""
	rest := []string{}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--explain" && i+1 < len(args) && !del:
			explain = args[i+1]
			i++
		case strings.HasPrefix(args[i], "-"):
			return errors.New(usage)
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) != 2 {
		return errors.New(usage)
	}
	store, key := rest[0], rest[1]
	if !envNameRE.MatchString(key) {
		return fmt.Errorf("key %q: letters, digits and _, not starting with a digit", key)
	}
	var value []byte
	if !del {
		v, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
		if err != nil {
			return err
		}
		if len(v) > 1<<20 {
			return errors.New("a value is at most 1 MiB")
		}
		value = []byte(strings.TrimSuffix(string(v), "\n")) // `echo x |` adds one
		if len(value) == 0 {
			return errors.New("no value on stdin (an empty key is a delete: jarvis2 delete-key)")
		}
	}
	r, err := readRoster()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var keys struct {
		State        kernel.SignedDoc `json:"state"`
		StoreKey     kernel.SignedDoc `json:"storeKey"`
		AgreementKey string           `json:"agreementKey"`
	}
	if err := c.json("GET", "/m/store-keys", nil, &keys); err != nil {
		return err
	}
	t, err := checkSealTargets(r, keys.State, keys.StoreKey, keys.AgreementKey)
	if err != nil {
		return err
	}
	req, err := keyWriteRequest(t, store, key, value, del, explain)
	if err != nil {
		return err
	}
	var out struct {
		Pulled []string `json:"pulled"`
	}
	if err := c.json("POST", "/m/stores/"+store+"/keys/"+key, req, &out); err != nil {
		return err
	}
	verb := map[bool]string{true: "deleted", false: "written"}[del]
	b, _ := json.Marshal(out.Pulled)
	fmt.Fprintf(os.Stderr, "%s %s in %s (backed up first). Running sessions whose grant names %s get it with their next pull (the router sent \"pull\" to %s).\n",
		key, verb, store, store, b)
	return nil
}
