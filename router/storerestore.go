package main

// Restoring a store to an earlier version (docs/DESIGN.md "Restoring a store"; core/kernel/secrets/history.go).
// Secrets keeps each store's last versions; putting one back is the phone's signature over secrets' exact begin
// document plus its shares of the keys put back, under one Face ID — no kit, no plaintext outside secrets. The
// router's part:
//
//	POST /api/secrets/stores/versions {store, nonce}     secrets' signed list, relayed (app, web)
//	POST /api/secrets/stores/restore/begin {store, seq}  secrets' signed begin document, relayed (the app's review page)
//	POST /api/stores/restore/finish {pending, signature, shares}
//	    the app, after Face ID: secrets checks the phone's signature, opens the keys put back and seals each one's
//	    backup to the master key; the router writes those backups (keys/<store>/<key>.json, writer "restore" with
//	    secrets' signed receipt) and only then commits; then every running machine whose grant names the store pulls
//	POST /setup/stores/versions                          the same list for the setup session
//	…/requests/restore {store, seq, explanation}         an Inbox request (web page, app, setup session; never a
//	                                                     session): it opens the app's restore review

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const requestKindRestore = "restore"

// restoreApproved: what secrets' finish answers
type restoreApproved struct {
	Receipt *Doc `json:"receipt"`
	Backups map[string]struct {
		E      string `json:"e"`
		Data   string `json:"data"`
		Sha256 string `json:"sha256"`
	} `json:"backups"`
}

type restoreReceipt struct {
	Kind    string `json:"kind"`
	Pending string `json:"pending"`
	Store   string `json:"store"`
	To      int    `json:"to"`
	Put     []struct {
		Key          string `json:"key"`
		E            string `json:"e"`
		DataSha256   string `json:"dataSha256"`
		BackupSha256 string `json:"backupSha256"`
	} `json:"put"`
	Remove []string `json:"remove"`
}

// FinishRestore: the phone's approval through secrets, the backups into the bucket, then the commit
func (r *Router) FinishRestore(body []byte) (map[string]any, error) {
	var in struct {
		Pending   string          `json:"pending"`
		Signature string          `json:"signature"`
		Shares    json.RawMessage `json:"shares"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Pending == "" || in.Signature == "" {
		return nil, &badRequest{"pending, signature and shares (the phone's)"}
	}
	b := backupBucketFromEnv()
	if b == nil {
		return nil, errors.New("the router has no backup credential (BACKUP_READ_ACCESS_KEY): nothing is restored without its backups")
	}
	status, raw, err := r.k.Raw("secrets", "POST", "/stores/restore/finish", body)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &KernelError{Part: "secrets", Status: status, Body: raw, Msg: "secrets: the restore was refused"}
	}
	var ap restoreApproved
	var rc restoreReceipt
	if json.Unmarshal(raw, &ap) != nil || ap.Receipt == nil || ap.Receipt.Decode(&rc) != nil || rc.Kind != "store-restore-approved" || rc.Pending != in.Pending {
		return nil, errors.New("secrets' restore answer isn't readable")
	}
	id, err := r.k.Identity("secrets")
	if err != nil {
		return nil, fmt.Errorf("secrets' identity isn't readable: %v", err)
	}
	ident, _ := json.Marshal(id)
	storeDocsMu.Lock()
	docs := r.readStoreDocs()[rc.Store]
	storeDocsMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	put := func(key string, obj map[string]any) error {
		obj["kind"], obj["store"], obj["key"], obj["secrets"], obj["explanation"], obj["at"] = "key-backup", rc.Store, key, json.RawMessage(ident), docs.Keys[key], now
		obj["writer"] = map[string]any{"by": "restore", "receipt": ap.Receipt}
		j, _ := json.Marshal(obj)
		return b.put("keys/"+rc.Store+"/"+key+".json", j)
	}
	// the backups first: secrets changes the store only once they are in the bucket
	for _, x := range rc.Put {
		bk, ok := ap.Backups[x.Key]
		if !ok || bk.Sha256 != x.BackupSha256 || backupSha(bk.E, bk.Data) != x.BackupSha256 {
			return nil, fmt.Errorf("secrets' backup of %s doesn't match its receipt: nothing restored", x.Key)
		}
		if err := put(x.Key, map[string]any{"deleted": false, "sealed": map[string]string{"e": bk.E, "data": bk.Data}, "backupSha256": x.BackupSha256,
			"e": x.E, "dataSha256": x.DataSha256}); err != nil {
			return nil, fmt.Errorf("the backups weren't written, so nothing was restored: %v", err)
		}
	}
	for _, k := range rc.Remove {
		if err := put(k, map[string]any{"deleted": true, "sealed": nil, "backupSha256": "", "e": "", "dataSha256": ""}); err != nil {
			return nil, fmt.Errorf("the backups weren't written, so nothing was restored: %v", err)
		}
	}
	done, err := r.k.SecretsDoc("/stores/restore/commit", map[string]string{"pending": in.Pending})
	if err != nil {
		return nil, err
	}
	log.Printf("store %s: version %d put back (phone-approved; %d keys back, %d removed)", rc.Store, rc.To, len(rc.Put), len(rc.Remove))
	r.dropRequests(func(q *InboxRequest) bool { return q.Kind == requestKindRestore && q.Params.Store == rc.Store }, outcomeApproved)
	pulled := r.pullHolders(rc.Store)
	return map[string]any{"ok": true, "restored": done, "pulled": pulled}, nil
}

func (r *Router) registerRestore(app appRoute, mux *http.ServeMux) {
	app("POST /api/secrets/stores/restore/begin", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		r.relay(w, "secrets", "POST", "/stores/restore/begin", b)
	})
	app("POST /api/stores/restore/finish", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		out, err := r.FinishRestore(b)
		if err != nil {
			writeWriteErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	setup := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, body []byte)) {
		mux.Handle(pattern, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 4<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		}))
	}
	setup("POST /setup/stores/versions", func(w http.ResponseWriter, req *http.Request, b []byte) {
		r.relay(w, "secrets", "POST", "/stores/versions", b)
	})
}
