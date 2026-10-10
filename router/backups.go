package main

// The store backups for the app's Recover (docs/DESIGN.md "Recover"). The router holds the backup bucket's
// read credential (BACKUP_READ_ACCESS_KEY / BACKUP_READ_SECRET_KEY, router secrets — a Hetzner S3 credential
// that bucket policies narrow to reads of jarvis2-backup-de0ch) and hands the app the locked backups as they
// are in the bucket: each one sealed to the master key and signed by its writer (the setup key), so the
// router can't read, change or forge one — it can only withhold a backup or serve an older signed version.
//
//	GET /api/backups → {bucket, objects: [{key, body}]}: every object under stores/ and sensitive/, body = the
//	                   object's text ({doc, sig}); 503 {error} without the credential.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type backupBucket struct {
	endpoint, region, bucket string
	accessKey, secretKey     string
	http                     *http.Client
	now                      func() time.Time
}

func backupBucketFromEnv() *backupBucket {
	ak, sk := os.Getenv("BACKUP_READ_ACCESS_KEY"), os.Getenv("BACKUP_READ_SECRET_KEY")
	if ak == "" || sk == "" {
		return nil
	}
	return &backupBucket{endpoint: strings.TrimSuffix(env("BACKUP_ENDPOINT", "https://fsn1.your-objectstorage.com"), "/"),
		region: env("BACKUP_REGION", "fsn1"), bucket: env("BACKUP_BUCKET", "jarvis2-backup-de0ch"),
		accessKey: ak, secretKey: sk, http: &http.Client{Timeout: 60 * time.Second}, now: time.Now}
}

// s3enc: AWS's URI encoding (unreserved characters kept; "/" kept in a key path)
func s3enc(s string, slash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' || slash && c == '/' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// get: a SigV4-signed, path-style GET of /<bucket>/<key>?<query>
func (b *backupBucket) get(key string, query map[string]string) ([]byte, error) {
	path := "/" + s3enc(b.bucket, false)
	if key != "" {
		path += "/" + s3enc(key, true)
	}
	ks := make([]string, 0, len(query))
	for k := range query {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	qs := make([]string, 0, len(ks))
	for _, k := range ks {
		qs = append(qs, s3enc(k, false)+"="+s3enc(query[k], false))
	}
	q := strings.Join(qs, "&")
	u, err := url.Parse(b.endpoint + path)
	if err != nil {
		return nil, err
	}
	u.RawQuery = q
	t := b.now().UTC()
	amz, day := t.Format("20060102T150405Z"), t.Format("20060102")
	empty := sha256.Sum256(nil)
	payload := hex.EncodeToString(empty[:])
	signed := "host;x-amz-content-sha256;x-amz-date"
	canonical := strings.Join([]string{"GET", path, q, "host:" + u.Host + "\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + amz + "\n", signed, payload}, "\n")
	scope := day + "/" + b.region + "/s3/aws4_request"
	ch := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	k := hmacSHA([]byte("AWS4"+b.secretKey), day)
	for _, p := range []string{b.region, "s3", "aws4_request"} {
		k = hmacSHA(k, p)
	}
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("x-amz-content-sha256", payload)
	req.Header.Set("x-amz-date", amz)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+b.accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmacSHA(k, toSign)))
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		var e struct{ Code string }
		xml.Unmarshal(body, &e)
		if e.Code == "" {
			e.Code = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("the backup bucket refused %s: %s", path, e.Code)
	}
	return body, nil
}

// list: every key under prefix (all pages)
func (b *backupBucket) list(prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := map[string]string{"list-type": "2", "prefix": prefix}
		if token != "" {
			q["continuation-token"] = token
		}
		body, err := b.get("", q)
		if err != nil {
			return nil, err
		}
		var l struct {
			Contents []struct{ Key string }
			IsTruncated           bool
			NextContinuationToken string
		}
		if err := xml.Unmarshal(body, &l); err != nil {
			return nil, fmt.Errorf("the backup bucket's listing isn't readable: %v", err)
		}
		for _, c := range l.Contents {
			keys = append(keys, c.Key)
		}
		if !l.IsTruncated || l.NextContinuationToken == "" {
			return keys, nil
		}
		token = l.NextContinuationToken
	}
}

type backupObject struct {
	Key  string `json:"key"`
	Body string `json:"body"`
}

// all: the store backups and the sensitivity markers, as they are
func (b *backupBucket) all() ([]backupObject, error) {
	out := []backupObject{}
	for _, prefix := range []string{"stores/", "sensitive/"} {
		keys, err := b.list(prefix)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if !strings.HasSuffix(k, ".json") {
				continue
			}
			body, err := b.get(k, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, backupObject{Key: k, Body: string(body)})
		}
	}
	return out, nil
}

func (r *Router) registerBackups(app func(string, http.HandlerFunc)) {
	app("GET /api/backups", func(w http.ResponseWriter, req *http.Request) {
		b := backupBucketFromEnv()
		if b == nil {
			writeJSON(w, 503, map[string]string{"error": "the router has no read key for the backups (BACKUP_READ_ACCESS_KEY)"})
			return
		}
		objs, err := b.all()
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"bucket": b.bucket, "objects": objs})
	})
}
