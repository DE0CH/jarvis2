package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// a bucket stand-in: two pages of stores/, one marker, and a check that every request is SigV4-signed
func TestBackupsServedAsTheyAreInTheBucket(t *testing.T) {
	objs := map[string]string{"stores/a.json": `{"doc":"a","sig":"x"}`, "stores/b.json": `{"doc":"b","sig":"y"}`, "sensitive/b.json": `{"doc":"m","sig":"z"}`, "stores/README": "no"}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if a := req.Header.Get("Authorization"); !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=ak/") || req.Header.Get("x-amz-date") == "" {
			w.WriteHeader(403)
			fmt.Fprint(w, "<Error><Code>AccessDenied</Code></Error>")
			return
		}
		if req.URL.Path == "/bkt" {
			q := req.URL.Query()
			p := q.Get("prefix")
			switch {
			case p == "stores/" && q.Get("continuation-token") == "":
				fmt.Fprint(w, `<ListBucketResult><Contents><Key>stores/a.json</Key></Contents><Contents><Key>stores/README</Key></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>t2</NextContinuationToken></ListBucketResult>`)
			case p == "stores/":
				fmt.Fprint(w, `<ListBucketResult><Contents><Key>stores/b.json</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
			default:
				fmt.Fprint(w, `<ListBucketResult><Contents><Key>sensitive/b.json</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
			}
			return
		}
		body, ok := objs[strings.TrimPrefix(req.URL.Path, "/bkt/")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, body)
	}))
	defer s.Close()
	r := newTestRouter(t)
	h := r.Handler()
	get := func() (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/backups", nil))
		var m map[string]any
		json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	if code, _ := get(); code != 503 {
		t.Fatalf("no credential: got %d", code)
	}
	for k, v := range map[string]string{"BACKUP_READ_ACCESS_KEY": "ak", "BACKUP_READ_SECRET_KEY": "sk", "BACKUP_ENDPOINT": s.URL, "BACKUP_BUCKET": "bkt"} {
		t.Setenv(k, v)
	}
	code, m := get()
	if code != 200 {
		t.Fatalf("got %d %v", code, m)
	}
	got := []string{}
	for _, o := range m["objects"].([]any) {
		ob := o.(map[string]any)
		if ob["body"] != objs[ob["key"].(string)] {
			t.Fatalf("%v changed on the way", ob["key"])
		}
		got = append(got, ob["key"].(string))
	}
	if strings.Join(got, ",") != "stores/a.json,stores/b.json,sensitive/b.json" {
		t.Fatalf("got %v", got)
	}
	t.Setenv("BACKUP_READ_ACCESS_KEY", "wrong")
	if code, m := get(); code != 502 || !strings.Contains(fmt.Sprint(m["error"]), "AccessDenied") {
		t.Fatalf("a refused read: got %d %v", code, m)
	}
}

// the real bucket, read-only (a list), when this session has the admin key: SigV4 against Hetzner itself
func TestBackupsSignatureOnHetzner(t *testing.T) {
	ak, sk := os.Getenv("HETZNER_S3_ACCESS_KEY"), os.Getenv("HETZNER_S3_SECRET_KEY")
	if ak == "" || os.Getenv("JARVIS2_LIVE_S3") != "1" {
		t.Skip("JARVIS2_LIVE_S3=1 with HETZNER_S3_* only")
	}
	t.Setenv("BACKUP_READ_ACCESS_KEY", ak)
	t.Setenv("BACKUP_READ_SECRET_KEY", sk)
	b := backupBucketFromEnv()
	objs, err := b.all()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d backup objects readable", len(objs))
}
