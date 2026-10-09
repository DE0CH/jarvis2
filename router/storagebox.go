package main

// The Storage Box (Hetzner, WebDAV over https on 443) with the router's own credentials: router env
// STORAGEBOX_HOST, STORAGEBOX_USER, STORAGEBOX_PASSWORD (k8s/secrets/router.enc.yaml). The archives of
// destroyed sessions live there, in Jarvis 1's layout (claude-records/<yyyy-mm-dd> <title>/), so Jarvis 1's
// transcript search picks them up.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type StorageBox struct {
	base, user, pass string
	http             *http.Client
}

// putBackoff: the wait before a PUT is retried (times the attempt)
var putBackoff = time.Second

var errNoStorageBox = errors.New("the router has no STORAGEBOX_HOST/USER/PASSWORD")

// recordsBoxFromEnv: nil when any of the three is missing
func recordsBoxFromEnv() *StorageBox {
	h, u, p := os.Getenv("STORAGEBOX_HOST"), os.Getenv("STORAGEBOX_USER"), os.Getenv("STORAGEBOX_PASSWORD")
	if h == "" || u == "" || p == "" {
		return nil
	}
	return newStorageBox("https://"+h, u, p)
}

func newStorageBox(base, user, pass string) *StorageBox {
	return &StorageBox{base: strings.TrimSuffix(base, "/") + "/", user: user, pass: pass, http: &http.Client{Timeout: 30 * time.Minute}}
}

func davURL(base, p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return base + strings.Join(segs, "/")
}

func (b *StorageBox) do(method, p string, body io.Reader, size int64, hdr map[string]string) (*http.Response, error) {
	u := davURL(b.base, p)
	if (method == "DELETE" && strings.HasSuffix(p, "/")) || method == "MKCOL" {
		u += "/"
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	req.SetBasicAuth(b.user, b.pass)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return b.http.Do(req)
}

// Mkcols: every segment of a directory path (an existing one answers 405, which is fine)
func (b *StorageBox) Mkcols(dir string) error {
	cur := ""
	for _, s := range strings.Split(strings.Trim(dir, "/"), "/") {
		if s == "" {
			continue
		}
		cur += s + "/"
		resp, err := b.do("MKCOL", strings.TrimSuffix(cur, "/"), nil, 0, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode != 405 {
			return fmt.Errorf("MKCOL %s: HTTP %d", cur, resp.StatusCode)
		}
	}
	return nil
}

// PutFile: a local file, three tries
func (b *StorageBox) PutFile(p, local string) error {
	var last error
	for i := 0; i < 3; i++ {
		f, err := os.Open(local)
		if err != nil {
			return err
		}
		fi, _ := f.Stat()
		last = b.put(p, f, fi.Size())
		f.Close()
		if last == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * putBackoff)
	}
	return last
}

func (b *StorageBox) PutBytes(p string, data []byte) error {
	var last error
	for i := 0; i < 3; i++ {
		if last = b.put(p, strings.NewReader(string(data)), int64(len(data))); last == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * putBackoff)
	}
	return last
}

func (b *StorageBox) put(p string, r io.Reader, size int64) error {
	resp, err := b.do("PUT", p, r, size, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: HTTP %d", p, resp.StatusCode)
	}
	return nil
}

// Get: nil, nil when the file is missing
func (b *StorageBox) Get(p string) ([]byte, error) {
	return b.get(p, nil)
}

// GetTail: the file's last n bytes (a server that ignores Range sends it whole; the caller copes)
func (b *StorageBox) GetTail(p string, n int) ([]byte, error) {
	return b.get(p, map[string]string{"Range": fmt.Sprintf("bytes=-%d", n)})
}

func (b *StorageBox) get(p string, hdr map[string]string) ([]byte, error) {
	resp, err := b.do("GET", p, nil, 0, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: HTTP %d", p, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// Download: a file to a local path (streamed); false when it is missing
func (b *StorageBox) Download(p, local string) (bool, error) {
	resp, err := b.do("GET", p, nil, 0, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("GET %s: HTTP %d", p, resp.StatusCode)
	}
	f, err := os.OpenFile(local, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err == nil, err
}

func (b *StorageBox) Exists(p string) (bool, error) {
	resp, err := b.do("HEAD", p, nil, 0, nil)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == 404:
		return false, nil
	case resp.StatusCode < 300:
		return true, nil
	}
	return false, fmt.Errorf("HEAD %s: HTTP %d", p, resp.StatusCode)
}

// Delete: a file, or a directory with a trailing "/" (whole); a missing one is fine
func (b *StorageBox) Delete(p string) error {
	resp, err := b.do("DELETE", p, nil, 0, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != 404 {
		return fmt.Errorf("DELETE %s: HTTP %d", p, resp.StatusCode)
	}
	return nil
}
