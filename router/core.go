package main

// The core's HTTP API (core/main.go). The router reads what it needs from the signed answers' payloads
// but doesn't rely on them for anything security-relevant; it passes the documents on unchanged.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Doc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

func (d *Doc) Decode(out any) error { return json.Unmarshal([]byte(d.Payload), out) }

type CoreClient struct {
	base string
	http *http.Client
}

// CoreError: the core refused; Body is its signed error document (relayed as is)
type CoreError struct {
	Status int
	Body   []byte
	Msg    string
}

func (e *CoreError) Error() string { return e.Msg }

func (c *CoreClient) Raw(method, path string, body []byte) (int, []byte, error) {
	req, _ := http.NewRequest(method, strings.TrimSuffix(c.base, "/")+path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, b, err
}

// Call: POST a JSON body, expect a signed document
func (c *CoreClient) Call(path string, in any) (*Doc, error) {
	body, _ := json.Marshal(in)
	status, b, err := c.Raw("POST", path, body)
	if err != nil {
		return nil, fmt.Errorf("core %s: %w", path, err)
	}
	var d Doc
	if status != 200 {
		msg := fmt.Sprintf("core %s: HTTP %d", path, status)
		var e struct{ Error string }
		if json.Unmarshal(b, &d) == nil && d.Decode(&e) == nil && e.Error != "" {
			msg = "core: " + e.Error
		}
		return nil, &CoreError{Status: status, Body: b, Msg: msg}
	}
	if err := json.Unmarshal(b, &d); err != nil || d.Payload == "" {
		return nil, fmt.Errorf("core %s: not a signed document", path)
	}
	return &d, nil
}

func (c *CoreClient) Key() (map[string]string, error) {
	status, b, err := c.Raw("GET", "/key", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("core /key: HTTP %d", status)
	}
	m := map[string]string{}
	return m, json.Unmarshal(b, &m)
}
