package main

// Request outcomes: what became of an Inbox request THIS session filed — approved, denied, lapsed (nobody answered),
// dropped (it left the Inbox without a decision) or failed (approved, but carrying it out failed) — as a notice. The
// text is built here from
//
//   - the session's own filing, as the guard kept it when the session filed it (records.go: by the filing id the proxy
//     gave the request, apiproxy.go), and
//   - texts built into this image for each outcome,
//
// while the router names only strictly formatted values per item: the item's index, the outcome (a word), an Inbox
// or session id and an HTTP status. Nothing the router says is checked against a signature here, so every text says
// it is Jarvis's report; what an approval actually changed shows up by itself (a new grant, a new store in
// ~/.secrets). Each item's outcome is told once (the records travel in the snapshot). Deyao's own words never come
// through here.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type OutcomeItem struct {
	Item    int    `json:"item"`
	Outcome string `json:"outcome"`
	Ref     string `json:"ref"`
	Status  int    `json:"status,omitempty"`
}

var (
	outcomeRefRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	outcomeSpace = regexp.MustCompile(`\s+`)
	filingPathRE = regexp.MustCompile(`^/api/(?:actions/)?(requests/[a-z/-]{1,40}|sessions)$`)
)

const outcomeFooter = "This is an automated message from Jarvis, not from Deyao, and not an answer to any open question."

// outcomeAsked: one item of the filing, as the session sent it
type outcomeAsked struct {
	Intent  string `json:"intent"`
	Repo    string `json:"repo"`
	Minutes int    `json:"minutes"`
	Store   string `json:"store"`
	Label   string `json:"label"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Cmd     string `json:"cmd"`
}

// short: the session's own words, on one line and capped
func short(s string, n int) string {
	s = strings.TrimSpace(outcomeSpace.ReplaceAllString(s, " "))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

func (a outcomeAsked) describe() string {
	switch a.Intent {
	case "repo/add":
		return fmt.Sprintf("a deploy key (read + push) for the repo %q", short(a.Repo, 200))
	case "repo/remove":
		return fmt.Sprintf("removing the deploy key of the repo %q", short(a.Repo, 200))
	case "terminal":
		return fmt.Sprintf("a shell grant on this session for %d min", a.Minutes)
	case "command":
		return fmt.Sprintf("running the command %q once on this session", short(a.Cmd, 200))
	case "unlock":
		return "unlocking the locked stores this session waits on"
	case "add-store":
		return fmt.Sprintf("adding the store %q to this session", short(a.Store, 80))
	case "new-session":
		return fmt.Sprintf("a new session %q", short(a.Label, 120))
	case "call":
		return fmt.Sprintf("the app API call %s %s", short(a.Method, 10), short(a.Path, 300))
	}
	return "a request"
}

// filingItems: the filing's items by index (a single request is item 0), and a batch's summary
func filingItems(f filing) (map[int]outcomeAsked, string, bool, error) {
	m := filingPathRE.FindStringSubmatch(f.Path)
	if m == nil {
		return nil, "", false, errors.New("the kept filing isn't an Inbox filing")
	}
	what := m[1]
	if what == "requests/batch" {
		var b struct {
			Summary string            `json:"summary"`
			Items   []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(f.Body, &b) != nil || len(b.Items) == 0 {
			return nil, "", false, errors.New("the kept batch has no items")
		}
		out := map[int]outcomeAsked{}
		for i, raw := range b.Items {
			var a outcomeAsked
			json.Unmarshal(raw, &a)
			out[i] = a
		}
		return out, short(b.Summary, 300), true, nil
	}
	var a outcomeAsked
	json.Unmarshal(f.Body, &a)
	if what == "sessions" {
		a.Intent = "new-session"
	} else {
		a.Intent = strings.TrimPrefix(what, "requests/")
	}
	return map[int]outcomeAsked{0: a}, "", false, nil
}

// outcomeLine: one item's sentence (the outcome's fixed text over what was asked)
func outcomeLine(a outcomeAsked, it OutcomeItem) (string, error) {
	what := a.describe()
	switch it.Outcome {
	case "approved":
		extra := ""
		switch a.Intent {
		case "add-store", "unlock":
			extra = " The store arrives with the next grant and pull: check ~/.secrets (load it in a shell with `set -a; . ~/.secrets; set +a`)."
		case "call":
			extra = fmt.Sprintf(" The call ran as Deyao and answered HTTP %d; read its result within 10 minutes: GET $JARVIS_URL/api/actions/requests/call/%s.", it.Status, it.Ref)
		case "new-session":
			extra = fmt.Sprintf(" Its session id is %s.", it.Ref)
		}
		return fmt.Sprintf("APPROVED: %s (Inbox %s), as Jarvis reports.%s", what, it.Ref, extra), nil
	case "denied":
		return fmt.Sprintf("DENIED: %s (Inbox %s), as Jarvis reports. Don't file the same again unchanged; carry on without it, or tell Deyao in the chat why it is needed.", what, it.Ref), nil
	case "lapsed":
		return fmt.Sprintf("LAPSED: %s (Inbox %s). Nobody answered it within 10 minutes, so it left the Inbox, as Jarvis reports. That is not a refusal: Deyao may not have seen it. File it again if it is still needed.", what, it.Ref), nil
	case "dropped":
		return fmt.Sprintf("DROPPED: %s (Inbox %s). It left the Inbox without a decision, as Jarvis reports (this session paused or ran on another machine, or what it was about went away). File it again if it is still needed.", what, it.Ref), nil
	case "failed":
		return fmt.Sprintf("FAILED: %s (Inbox %s). It was approved but carrying it out failed, as Jarvis reports. Check the state yourself and file it again if it is still needed.", what, it.Ref), nil
	}
	return "", fmt.Errorf("not an outcome: %q", it.Outcome)
}

// outcomeText: the request-outcome notice's text, each item told once
func (g *guard) outcomeText(n Notice) (string, error) {
	if !textIDRE.MatchString(n.Filing) || len(n.Items) == 0 || len(n.Items) > 20 {
		return "", errors.New("request-outcome: no filing or items")
	}
	var text string
	err := g.rec.update(func(r *recordsData) error {
		f, ok := r.Filings[n.Filing]
		if !ok {
			return errors.New("request-outcome: no filing of this session has that id")
		}
		items, summary, batch, err := filingItems(f)
		if err != nil {
			return err
		}
		list := append([]OutcomeItem{}, n.Items...)
		sort.Slice(list, func(i, j int) bool { return list[i].Item < list[j].Item })
		lines := []string{}
		seen := map[int]bool{}
		if f.Told == nil {
			f.Told = map[string]bool{}
		}
		for _, it := range list {
			a, ok := items[it.Item]
			if !ok || seen[it.Item] || !outcomeRefRE.MatchString(it.Ref) || it.Status < 0 || it.Status > 999 {
				return errors.New("request-outcome: not an item of the filing, or not an id or status")
			}
			if f.Told[strconv.Itoa(it.Item)] {
				return fmt.Errorf("the outcome of item %d of this filing was already delivered", it.Item)
			}
			seen[it.Item] = true
			l, err := outcomeLine(a, it)
			if err != nil {
				return err
			}
			if batch {
				l = fmt.Sprintf("%d. %s", it.Item+1, l)
			}
			lines = append(lines, l)
		}
		for _, it := range list {
			f.Told[strconv.Itoa(it.Item)] = true
		}
		r.Filings[n.Filing] = f
		if batch {
			text = fmt.Sprintf("[Inbox outcome] Deyao's Inbox has decided %d of the %d items of the batch this session filed (its summary: %q):\n%s\n%s",
				len(lines), len(items), summary, strings.Join(lines, "\n"), outcomeFooter)
		} else {
			text = fmt.Sprintf("[Inbox outcome] A request this session filed has been decided. %s %s", lines[0], outcomeFooter)
		}
		return nil
	})
	return text, err
}
