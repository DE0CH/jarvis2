package main

import (
	"strings"
	"testing"
)

func TestParseTranscript(t *testing.T) {
	text := strings.Join([]string{
		`{"type":"user","sessionId":"abc","message":{"content":"first <system-reminder>hidden</system-reminder>"}}`,
		`not json`,
		`{"type":"ai-title","aiTitle":"Auto"}`,
		`{"type":"queue-operation","operation":"enqueue","content":"typed mid-turn"}`,
		`{"type":"queue-operation","operation":"enqueue","content":"<task-notification>x</task-notification>"}`,
		`{"type":"assistant","message":{"content":[{"type":"tool_use"},{"type":"text","text":"reply"}]}}`,
		`{"type":"user","message":{"content":"typed mid-turn"}}`,
		`{"type":"assistant","isSidechain":true,"message":{"content":"subagent"}}`,
		`{"type":"user","isMeta":true,"message":{"content":"meta"}}`,
		`{"type":"custom-title","customTitle":"Renamed"}`,
		`{"type":"assistant","message":{"content":"` + strings.Repeat("x", 30) + `"}}`,
	}, "\n")
	tl := parseTranscript(text, false, 40, 20)
	if tl.Title != "Renamed" || tl.SessionID != "abc" {
		t.Fatalf("%+v", tl)
	}
	var got []string
	for _, m := range tl.Messages {
		got = append(got, m.Role+":"+m.Text)
	}
	want := []string{"user:first", "assistant:reply", "user:typed mid-turn", "assistant:" + strings.Repeat("x", 20) + " …"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	// a tail read drops its partial first line; max keeps the last messages
	tl = parseTranscript(`"content":"cut"}}`+"\n"+text, true, 1, 4000)
	if len(tl.Messages) != 1 || !strings.HasPrefix(tl.Messages[0].Text, "xxx") {
		t.Fatalf("%+v", tl.Messages)
	}
	if s := snippet(Tail{Messages: []TailMessage{{Role: "user", Text: "a\n\n b"}}}); s.Text != "a b" {
		t.Fatal(s.Text)
	}
}

func TestIsTranscript(t *testing.T) {
	for name, want := range map[string]bool{
		".claude/projects/p/x.jsonl":           true,
		".claude/projects/p/sub/x.jsonl":       false,
		".claude/projects/p/x.json":            false,
		"workspace/.claude/projects/p/x.jsonl": false,
	} {
		if isTranscript(name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
}
