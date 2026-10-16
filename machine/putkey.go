package main

// Writing one key into a store from a session (Deyao, 2026-10-13: any session with a valid machine key may write a key,
// with no approval: it can't read the store, and the key's backup keeps every earlier value). The value never leaves
// this machine in the clear: it is sealed to the store key P + K (only the phone and the core together open it) and,
// for its backup, to the master key (only Deyao's kit opens it), and this machine signs both (core.WriterText). The
// store key, the master key and the phone come from the core's signed documents, checked against the core key this
// machine was started with, so the router can't hand it a key of its own.
//
//	jarvis2 put-key STORE KEY [--explain TEXT] < value     the value from stdin (never an argument)
//	jarvis2 delete-key STORE KEY
//
// The session's own ~/.secrets doesn't change: every running session holding the store (this one too) gets the new
// value once Deyao allows the refresh the router files (the phone's unlock), and then pulls it by itself (supervisor:
// refresh-secrets).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// writerText: core.WriterText
func writerText(store, key, e, data, backupSha string) string {
	sum := ""
	if data != "" {
		h := sha256.Sum256([]byte(data))
		sum = hex.EncodeToString(h[:])
	}
	return "jarvis2-store-key\n" + store + "\n" + key + "\n" + e + "\n" + sum + "\n" + backupSha
}

// sealParts: ephemeral ECDH with the recipient point, HKDF-SHA256(info), AES-256-GCM (nonce ‖ ciphertext ‖ tag)
func sealParts(recipientB64 string, plain []byte, info string, aad []byte) (string, string, error) {
	rb, err := b64.DecodeString(recipientB64)
	if err != nil {
		return "", "", err
	}
	r, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		return "", "", err
	}
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	x, err := e.ECDH(r)
	if err != nil {
		return "", "", err
	}
	k, err := hkdf.Key(sha256.New, x, nil, info, 32)
	if err != nil {
		return "", "", err
	}
	return b64.EncodeToString(e.PublicKey().Bytes()), b64.EncodeToString(gcmSeal(k, plain, aad)), nil
}

func gcmSeal(key, plain, aad []byte) []byte {
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}

// sealTargets: the store key and the master key, from the core's signed documents (checked with the core key)
func sealTargets(c *client, coreKey string) (storeKey, master string, err error) {
	var out struct {
		Identity struct {
			SigningKey string     `json:"signingKey"`
			State      *SignedDoc `json:"state"`
		} `json:"identity"`
		StoreKey *SignedDoc `json:"storeKey"`
	}
	if err := c.json("GET", "/m/store-key", nil, &out); err != nil {
		return "", "", err
	}
	var st struct {
		Kind   string `json:"kind"`
		Master string `json:"master"`
		Phone  *struct {
			AgreementKey string `json:"agreementKey"`
		} `json:"phone"`
	}
	if out.Identity.SigningKey != coreKey || verifyDoc(coreKey, out.Identity.State, &st) != nil || st.Kind != "core-state" || st.Master == "" || st.Phone == nil {
		return "", "", errors.New("the core's state isn't signed by this machine's core, or the core isn't set up")
	}
	var sk struct {
		Kind, Phone, StoreKey string
	}
	if verifyDoc(coreKey, out.StoreKey, &sk) != nil || sk.Kind != "store-key" || sk.Phone != st.Phone.AgreementKey || sk.StoreKey == "" {
		return "", "", errors.New("the store key isn't the core's for its phone")
	}
	return sk.StoreKey, st.Master, nil
}

// keyWriteRequest: what the router takes (router/storedocs.go keyWriteIn), sealed and signed here
func keyWriteRequest(storeKey, master string, sig *ecdh.PrivateKey, store, key string, value []byte, del bool, explanation string) (map[string]any, error) {
	req := map[string]any{"delete": del, "explanation": explanation}
	e, data, backupSha := "", "", ""
	if !del {
		dk := make([]byte, 32)
		rand.Read(dk)
		var wrapped string
		var err error
		if e, wrapped, err = sealParts(storeKey, dk, "jarvis2/store-data-key", nil); err != nil {
			return nil, fmt.Errorf("the store key: %w", err)
		}
		data = b64.EncodeToString(gcmSeal(dk, value, []byte(store+"\n"+key)))
		be, bd, err := sealParts(master, value, "jarvis2/backup", []byte(store+"\n"+key))
		if err != nil {
			return nil, fmt.Errorf("the master key: %w", err)
		}
		h := sha256.Sum256([]byte(be + "\n" + bd))
		backupSha = hex.EncodeToString(h[:])
		req["wrapped"] = map[string]string{"e": e, "wrapped": wrapped}
		req["data"], req["backup"], req["backupSha256"] = data, map[string]string{"e": be, "data": bd}, backupSha
	}
	s, err := sign(sig, []byte(writerText(store, key, e, data, backupSha)))
	if err != nil {
		return nil, err
	}
	req["sig"] = s
	return req, nil
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
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	storeKey, master, err := sealTargets(c, coreKey)
	if err != nil {
		return err
	}
	priv, err := loadPrivate()
	if err != nil {
		return err
	}
	req, err := keyWriteRequest(storeKey, master, priv.sig, store, key, value, del, explain)
	if err != nil {
		return err
	}
	var out struct {
		RefreshAsked []string `json:"refreshAsked"`
	}
	if err := c.json("POST", "/m/stores/"+store+"/keys/"+key, req, &out); err != nil {
		return err
	}
	verb := map[bool]string{true: "deleted", false: "written"}[del]
	fmt.Fprintf(os.Stderr, "%s %s in %s (backed up first). Sessions holding %s get it once Deyao allows their refresh in the Jarvis 2 Inbox (asked for %d running session(s)); this session's ~/.secrets changes then too, if it holds the store.\n",
		key, verb, store, store, len(out.RefreshAsked))
	return nil
}

// refreshFromRouter: the router's refresh-secrets (an unlock for this machine's cert went through): pull again with the
// newest cert and rewrite ~/.secrets and the deploy keys, under the same lock as every other writer of them
func refreshFromRouter(c *client) {
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		log.Printf("refresh-secrets: %v", err)
		return
	}
	n, err := refreshSecrets(func() error {
		doc, ok := newestCert(c, coreKey, c.me)
		if !ok {
			return errors.New("the router has no cert for this machine")
		}
		raw, _ := json.Marshal(doc)
		return os.WriteFile(certPath, raw, 0o644)
	}, func() (map[string]string, error) { return pullSecrets(c, coreKey, c.me) })
	if err != nil {
		log.Printf("refresh-secrets: %v", err)
		return
	}
	log.Printf("refresh-secrets: ~/.secrets rewritten with the stores as they are now (%d keys)", n)
}
