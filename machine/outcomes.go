package main

// Request outcomes (router/outcomes.go): what became of an Inbox request THIS session filed — approved, denied, lapsed
// (nobody answered within 10 minutes), dropped (it left the Inbox without a decision) or failed (approved, but
// carrying it out failed) — delivered into the harness. The text is built here, from
//
//   - the session's own filing, exactly as one of this line's machines signed it (what was asked: the intent and
//     its arguments, read from that body), and
//   - texts built into this image for each outcome,
//
// and the router names only strict-format values per item: the outcome (a word), an Inbox or session id, an HTTP
// status (a number), and a proof. An approval that leaves a signed trace must carry it and it is checked here (a
// bad or missing proof refuses the whole delivery): a grant is the phone-signed grant for this line (the phone key
// from this machine's core-signed cert), an added store is this machine's new core-signed cert naming it, a new
// session is the core's approval by the phone of a new line whose config holds the proposal's label and prompt, a
// deploy key is the core's signed key answer for the repo. An unlock and an API call leave nothing signed, and a
// denial, a lapse, a drop or a failure is a non-event: those texts say they are Jarvis's report. Deyao's own words
// never come through here.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type OutcomeItem struct {
	Item    int        `json:"item"`
	Outcome string     `json:"outcome"`
	Ref     string     `json:"ref"`
	Status  int        `json:"status,omitempty"`
	Proof   *SignedDoc `json:"proof,omitempty"`
}

// outcomeRecord: what the core attested (router/outcomes.go builds the same bytes)
type outcomeRecord struct {
	Request string              `json:"request"`
	Items   []outcomeRecordItem `json:"items"`
}

type outcomeRecordItem struct {
	Item    int    `json:"item"`
	Outcome string `json:"outcome"`
	Ref     string `json:"ref"`
	Status  int    `json:"status"`
	Proof   string `json:"proof"`
}

var (
	outcomeRefRE  = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	outcomePathRE = regexp.MustCompile(`^/m/api/(?:actions/)?(requests/(?:repo/add|repo/remove|grant|unlock|add-store|call|batch)|sessions)$`)
	outcomeSpace  = regexp.MustCompile(`\s+`)
)

// outcomeCoreKey: the core's key (a seam for tests)
var outcomeCoreKey = func() (string, error) { return readTrim(coreKeyPath) }

const outcomeFooter = "This is an automated message from Jarvis, not from Deyao, and not an answer to any open question."

// outcomeAsked: one item of the filing, as the session signed it
type outcomeAsked struct {
	Intent    string `json:"intent"`
	Repo      string `json:"repo"`
	Holder    string `json:"holder"`
	Minutes   int    `json:"minutes"`
	Days      int    `json:"days"`
	Store     string `json:"store"`
	Label     string `json:"label"`
	Prompt    string `json:"prompt"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Summary   string `json:"summary"`
	Sensitive bool   `json:"sensitive"`
	NoStore   bool   `json:"noStore"` // repo/add: the store isn't to come into this session
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
	case "grant":
		if a.Days > 0 {
			return fmt.Sprintf("a standing rule letting %q into this session for %d days", short(a.Holder, 40), a.Days)
		}
		m := a.Minutes
		if m == 0 {
			m = 10
		}
		return fmt.Sprintf("a grant letting %q into this session for %d min", short(a.Holder, 40), m)
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

// outcomeFiling: the filing's items by index (a single request is item 0), and a batch's summary
func outcomeFiling(r *SignedRequest, keys []string) (map[int]outcomeAsked, string, bool, error) {
	body, err := ownRequestBody(r, keys)
	if err != nil {
		return nil, "", false, err
	}
	m := outcomePathRE.FindStringSubmatch(r.Path)
	if r.Method != "POST" || m == nil {
		return nil, "", false, errors.New("the signed request isn't one of this session's Inbox filings")
	}
	what := m[1]
	if what == "requests/batch" {
		var b struct {
			Summary string            `json:"summary"`
			Items   []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(body, &b) != nil || len(b.Items) == 0 {
			return nil, "", false, errors.New("the signed batch has no items")
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
	if json.Unmarshal(body, &a) != nil {
		return nil, "", false, errors.New("the signed request isn't JSON")
	}
	switch what {
	case "sessions":
		a.Intent = "new-session"
	default:
		a.Intent = strings.TrimPrefix(what, "requests/")
	}
	return map[int]outcomeAsked{0: a}, "", false, nil
}

// repoName: owner/name, lower case, from the forms the router takes (owner/name, https or ssh URL, .git)
func repoName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{"https://github.com/", "http://github.com/", "git@github.com:", "ssh://git@github.com/", "github.com/"} {
		s = strings.TrimPrefix(s, p)
	}
	return strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
}

// outcomeResult: an approval's checked proof → what it established (a sentence), or an error refusing the delivery
func outcomeResult(a outcomeAsked, it OutcomeItem, cert Cert) (string, error) {
	need := func() error {
		if it.Proof == nil {
			return fmt.Errorf("an approval of %s needs its signed proof, and none came", a.Intent)
		}
		return nil
	}
	switch a.Intent {
	case "grant":
		if err := need(); err != nil {
			return "", err
		}
		var g Grant
		if cert.Phone == "" || verifyDoc(cert.Phone, it.Proof, &g) != nil || g.Session != cert.Line || g.Scope != "shell" {
			return "", errors.New("the grant isn't the phone's, for this session")
		}
		if g.Kind == "rule" {
			return fmt.Sprintf("Checked: the phone signed a standing rule for this session until %s.", g.Until), nil
		}
		return fmt.Sprintf("Checked: the phone signed a grant for this session until %s (UTC).", g.Expires), nil
	case "add-store":
		if err := need(); err != nil {
			return "", err
		}
		key, err := outcomeCoreKey()
		if err != nil {
			return "", err
		}
		var c Cert
		if verifyDoc(key, it.Proof, &c) != nil || c.Machine == nil || cert.Machine == nil || c.Machine.ID != cert.Machine.ID {
			return "", errors.New("the proof isn't a core-signed cert of this machine")
		}
		for _, s := range c.Stores {
			if s == a.Store {
				return fmt.Sprintf("Checked: this machine's new core-signed cert names the store %q. If `jarvis2-request add-store` filed it, a background waiter pulls it into ~/.secrets by itself (~/.jarvis2-await-%s.log); then load it in a shell with `set -a; . ~/.secrets; set +a`.", a.Store, a.Store), nil
			}
		}
		return "", errors.New("the cert doesn't name the store")
	case "new-session":
		if err := need(); err != nil {
			return "", err
		}
		key, err := outcomeCoreKey()
		if err != nil {
			return "", err
		}
		var ap struct {
			Kind    string `json:"kind"`
			By      string `json:"by"`
			Request struct {
				Predecessor *SignedDoc `json:"predecessor"`
				Options     struct {
					Config string `json:"config"`
				} `json:"options"`
			} `json:"request"`
		}
		if verifyDoc(key, it.Proof, &ap) != nil || ap.Kind != "approval" || ap.By != "phone" || ap.Request.Predecessor != nil {
			return "", errors.New("the proof isn't the core's approval, by the phone, of a new line")
		}
		var cfg struct {
			Label  string `json:"label"`
			Prompt string `json:"prompt"`
		}
		if json.Unmarshal([]byte(ap.Request.Options.Config), &cfg) != nil || cfg.Label != a.Label || cfg.Prompt != a.Prompt {
			return "", errors.New("the approved session isn't the one this session proposed")
		}
		return fmt.Sprintf("Checked: the core's approval (by the phone) of a new session with this proposal's title and prompt. Its session id is %s; it is starting now.", it.Ref), nil
	case "repo/add", "repo/remove":
		if err := need(); err != nil {
			return "", err
		}
		key, err := outcomeCoreKey()
		if err != nil {
			return "", err
		}
		var k struct {
			Kind string `json:"kind"`
			Repo string `json:"repo"`
		}
		want := map[string]string{"repo/add": "deploy-key-added", "repo/remove": "deploy-key-removed"}[a.Intent]
		if verifyDoc(key, it.Proof, &k) != nil || k.Kind != want || repoName(k.Repo) != repoName(a.Repo) {
			return "", errors.New("the proof isn't the core's key answer for that repo")
		}
		if a.Intent == "repo/add" {
			if a.NoStore {
				return "Checked: the core's signed answer says the deploy key was added. It is in a store of its own, which no session holds until it is added to one (`jarvis2-request add-store <that store>`; the app's Repos list names it).", nil
			}
			return "Checked: the core's signed answer says the deploy key was added, in a store of its own. That store comes into this session in the same approval (while it runs): the waiter `jarvis2-request add-repo` started pulls it into ~/.secrets and sets up the repo's SSH key by itself (~/.jarvis2-await-github-*.log). If it hasn't arrived (this session wasn't running, or the app asked for it separately and it lapsed), ask for it with `jarvis2-request add-store <that store>`.", nil
		}
		return "Checked: the core's signed answer says the deploy key was removed.", nil
	case "unlock":
		return "Nothing signed comes with an unlock: this is Jarvis's report. The stores open by themselves once the unlock is through (the machine's secrets pull retries).", nil
	case "call":
		return fmt.Sprintf("Nothing signed comes with an API call's approval: this is Jarvis's report. The call ran as Deyao and answered HTTP %d; read its result within 10 minutes: GET $JARVIS_URL/api/actions/requests/call/%s.", it.Status, it.Ref), nil
	}
	return "Nothing signed comes with it: this is Jarvis's report.", nil
}

// outcomeLine: one item's sentence (the outcome's fixed text over what was asked)
func outcomeLine(a outcomeAsked, it OutcomeItem, cert Cert) (string, error) {
	what := a.describe()
	switch it.Outcome {
	case "approved":
		res, err := outcomeResult(a, it, cert)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("APPROVED: %s (Inbox %s). %s", what, it.Ref, res), nil
	case "denied":
		return fmt.Sprintf("DENIED: %s (Inbox %s). Deyao denied it, as Jarvis reports (a denial leaves nothing signed). Don't file the same again unchanged; carry on without it, or tell Deyao in the chat why it is needed.", what, it.Ref), nil
	case "lapsed":
		return fmt.Sprintf("LAPSED: %s (Inbox %s). Nobody answered it within 10 minutes, so it left the Inbox, as Jarvis reports. That is not a refusal: Deyao may not have seen it. File it again if it is still needed.", what, it.Ref), nil
	case "dropped":
		return fmt.Sprintf("DROPPED: %s (Inbox %s). It left the Inbox without a decision, as Jarvis reports (this session paused or ran on another machine, or what it was about went away). File it again if it is still needed.", what, it.Ref), nil
	case "failed":
		return fmt.Sprintf("FAILED: %s (Inbox %s). It was approved but carrying it out failed, as Jarvis reports. Check the state yourself and file it again if it is still needed.", what, it.Ref), nil
	}
	return "", fmt.Errorf("not an outcome: %q", it.Outcome)
}

// outcomeText: the request-outcome delivery's text and the bytes the core attested
func outcomeText(d Delivery, keys []string) (string, []byte, error) {
	if d.Request == nil || len(d.Outcomes) == 0 || len(d.Outcomes) > 20 {
		return "", nil, errors.New("request-outcome: no request or items")
	}
	items, summary, batch, err := outcomeFiling(d.Request, keys)
	if err != nil {
		return "", nil, err
	}
	cert, err := currentCert()
	if err != nil {
		return "", nil, fmt.Errorf("no valid cert: %v", err)
	}
	list := append([]OutcomeItem{}, d.Outcomes...)
	sort.Slice(list, func(i, j int) bool { return list[i].Item < list[j].Item })
	rec := outcomeRecord{Request: d.Request.Sig}
	lines := []string{}
	seen := map[int]bool{}
	for _, it := range list {
		a, ok := items[it.Item]
		if !ok || seen[it.Item] || !outcomeRefRE.MatchString(it.Ref) || it.Status < 0 || it.Status > 999 {
			return "", nil, errors.New("request-outcome: not an item of the filing, or not an id or status")
		}
		seen[it.Item] = true
		l, err := outcomeLine(a, it, cert)
		if err != nil {
			return "", nil, err
		}
		if batch {
			l = fmt.Sprintf("%d. %s", it.Item+1, l)
		}
		lines = append(lines, l)
		ph := ""
		if it.Proof != nil {
			ph = proofHash(it.Proof)
		}
		rec.Items = append(rec.Items, outcomeRecordItem{Item: it.Item, Outcome: it.Outcome, Ref: it.Ref, Status: it.Status, Proof: ph})
	}
	attested, _ := json.Marshal(rec)
	var t string
	if batch {
		t = fmt.Sprintf("[Inbox outcome] Deyao's Inbox has decided %d of the %d items of the batch this session filed (its summary: %q):\n%s\n%s",
			len(lines), len(items), summary, strings.Join(lines, "\n"), outcomeFooter)
	} else {
		t = fmt.Sprintf("[Inbox outcome] A request this session filed has been decided. %s %s", lines[0], outcomeFooter)
	}
	return t, attested, nil
}

func proofHash(p *SignedDoc) string {
	sum := sha256.Sum256([]byte(p.Payload + "\n" + p.Sig))
	return hex.EncodeToString(sum[:])
}

// outcomeNotReplayed: each item of a filing is told once (deliveredFile, which travels in the snapshot)
func outcomeNotReplayed(d Delivery, now time.Time, record bool) error {
	deliveredMu.Lock()
	defer deliveredMu.Unlock()
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, deliveredFile)
	seen := map[string]delivered{}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &seen)
	}
	for _, it := range d.Outcomes {
		if _, ok := seen[fmt.Sprintf("outcome %s %d", d.Request.Sig, it.Item)]; ok {
			return fmt.Errorf("the outcome of item %d of this filing was already delivered", it.Item)
		}
	}
	if !record {
		return nil
	}
	for _, it := range d.Outcomes {
		seen[fmt.Sprintf("outcome %s %d", d.Request.Sig, it.Item)] = delivered{At: now.Unix()}
	}
	b, _ := json.Marshal(seen)
	return os.WriteFile(p, b, 0o600)
}
