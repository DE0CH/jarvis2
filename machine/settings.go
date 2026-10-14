package main

// What shapes this machine (docs/DESIGN.md "Target design"): the image (its digest is the source's), the source's start
// settings, the snapshot whose hash the source names, and the grant. Nothing the router says on its own reaches a program
// or the agent, except a few values whose strict format can't carry an instruction (FormatExceptions). So:
//
//   - the env: the machine throws away whatever env it was started with and keeps only the image's own, Fly's FLY_*
//     values, and what the spawner set in the machine's Fly config — its key, the kernel roster and the router's
//     address (cleanEnv) — before anything else runs;
//   - the start settings come from the source the spawner started this machine from (checked against the source's own
//     notarized cert: boot.go), read strictly: a field the guard doesn't know refuses the boot. They are fixed for the
//     machine's life; in particular the permission mode is read once from them and nothing changes it.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/DE0CH/jarvis2/core/kernel"
)

const imageEnvFile = "/opt/jarvis2/image.env" // the image's own ENV, written at build (session-image/Dockerfile)

// The spawner's names in the machine's Fly config (core/kernel/spawner)
const (
	spawnerKeyEnv = "JARVIS2_SPAWNER_KEY"
	rosterEnv     = "JARVIS2_ROSTER"
	routerURLEnv  = "JARVIS2_URL"
)

// what Fly itself sets in a machine (values only: they never name code)
var flyEnv = []string{"FLY_MACHINE_ID", "FLY_APP_NAME", "FLY_REGION", "FLY_PRIVATE_IP", "FLY_PUBLIC_IP", "FLY_IMAGE_REF",
	"FLY_ALLOC_ID", "FLY_VM_MEMORY_MB", "PRIMARY_REGION"}

var (
	flyValueRE = regexp.MustCompile(`^[A-Za-z0-9:._@/+-]{0,200}$`)
	b64KeyRE   = regexp.MustCompile(`^[A-Za-z0-9+/]{60,120}={0,2}$`)
	routerRE   = regexp.MustCompile(`^http://[A-Za-z0-9][A-Za-z0-9._-]{0,200}(:[0-9]{1,5})?/?$`)
	// a GitHub owner/name: an owner never starts with a dot, a name is never . or ..
	ghRepoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$`)
)

// cleanEnv: the env this machine runs with, from the env it was started with: the image's ENV (imageEnv, fixed by
// the image digest), Fly's values, the spawner's key, the roster and the router's address. Everything else is dropped.
func cleanEnv(started []string, imageEnv []string) ([]string, error) {
	m := map[string]string{}
	for _, kv := range imageEnv {
		if k, v, ok := strings.Cut(kv, "="); ok && envNameRE.MatchString(k) {
			m[k] = v
		}
	}
	if m["PATH"] == "" {
		m["PATH"] = "/home/claude/.local/bin:/usr/local/bin:/usr/bin:/bin"
	}
	m["HOME"], m["USER"], m["LOGNAME"], m["SHELL"] = "/home/claude", "claude", "claude", "/bin/bash"
	if m["LANG"] == "" {
		m["LANG"] = "C.UTF-8"
	}
	got := map[string]string{}
	for _, kv := range started {
		if k, v, ok := strings.Cut(kv, "="); ok {
			got[k] = v
		}
	}
	for _, k := range flyEnv {
		if v, ok := got[k]; ok && flyValueRE.MatchString(v) {
			m[k] = v
		}
	}
	key := strings.TrimSpace(got[spawnerKeyEnv])
	if !b64KeyRE.MatchString(key) {
		return nil, errors.New("no spawner key in the machine's config (" + spawnerKeyEnv + ")")
	}
	m[spawnerKeyEnv] = key
	if _, err := parseRoster(got[rosterEnv], key); err != nil {
		return nil, err
	}
	m[rosterEnv] = got[rosterEnv]
	if u := strings.TrimSpace(got[routerURLEnv]); routerRE.MatchString(u) {
		m[routerURLEnv] = u
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

// parseRoster: the kernel's public keys, as the spawner put them in the machine's Fly config next to its own key
// (JARVIS2_ROSTER, the JSON of kernel.Roster): every key a P-256 point, and the spawner's the one the config names
func parseRoster(raw, spawnerKey string) (kernel.Roster, error) {
	var r kernel.Roster
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, fmt.Errorf("no kernel roster in the machine's config (%s): %v", rosterEnv, err)
	}
	for role, k := range map[string]string{"notary": r.Notary, "notarizer": r.Notarizer, "mover": r.Mover, "merger": r.Merger,
		"spawner": r.Spawner, "identity": r.Identity, "gullible": r.Gullible, "secrets": r.Secrets, "phone": r.Phone, "root": r.Root} {
		if _, err := kernel.ParsePoint(k); err != nil {
			return r, fmt.Errorf("the roster's %s key: %v", role, err)
		}
	}
	if r.Spawner != spawnerKey {
		return r, errors.New("the roster's spawner key isn't the one in the machine's config")
	}
	return r, nil
}

func readImageEnv() []string {
	b, err := os.ReadFile(imageEnvFile)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// ensureCleanEnv: boot's first step. When the env isn't already the clean one, re-exec with it (so even the Go
// runtime's own variables, read before main, come from the clean env).
func ensureCleanEnv() error {
	clean, err := cleanEnv(os.Environ(), readImageEnv())
	if err != nil {
		return err
	}
	cur := append([]string(nil), os.Environ()...)
	sort.Strings(cur)
	if strings.Join(cur, "\x00") == strings.Join(clean, "\x00") {
		return nil
	}
	dropped := []string{}
	keep := map[string]bool{}
	for _, kv := range clean {
		k, _, _ := strings.Cut(kv, "=")
		keep[k] = true
	}
	for _, kv := range cur {
		if k, _, _ := strings.Cut(kv, "="); !keep[k] {
			dropped = append(dropped, k)
		}
	}
	if len(dropped) > 0 {
		log.Printf("env: dropping what the spawner didn't set: %s", strings.Join(dropped, " "))
	}
	return syscall.Exec("/proc/self/exe", os.Args, clean)
}

// ---- the start settings (the source's) ---------------------------------------------------------------------

// Settings: a source's start settings (kernel.Object.Settings, exact JSON the kernel never reads; the phone shows them
// before Face ID). docs/API-grants.md "Start settings".
type Settings struct {
	V              int             `json:"v"`
	Session        string          `json:"session"`        // the router's session id
	Harness        string          `json:"harness"`        // claude | opencode | openclaw | task:<template>
	PermissionMode string          `json:"permissionMode"` // auto | bypass: fixed for the session's life
	Title          string          `json:"title,omitempty"`
	Model          string          `json:"model,omitempty"`
	Repos          []string        `json:"repos,omitempty"`
	Content        []string        `json:"content,omitempty"` // content stores: content-sync pulls each into ~/content/<name>/
	OneShot        bool            `json:"oneShot,omitempty"`
	APIProxy       bool            `json:"apiProxy,omitempty"`
	Prompt         string          `json:"prompt,omitempty"`      // typed at the start of a source the phone made
	Attachments    []AttachmentRef `json:"attachments,omitempty"` // with that prompt
	Rollback       string          `json:"rollback,omitempty"`    // a source the phone made: drop transcript lines from the first holding it
	Task           *TaskConfig     `json:"task,omitempty"`
}

type AttachmentRef struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type TaskConfig struct {
	Instance string         `json:"instance"`
	Name     string         `json:"name"`
	Params   map[string]any `json:"params"`
}

var (
	modelRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:\[\]-]{0,99}$`)
	contentRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)
)

// parseSettings: strictly — an unknown field, a missing session, harness or permission mode, or a malformed value
// refuses the boot (the phone showed every field; this machine must not silently skip or default what Deyao approved)
func parseSettings(raw string) (Settings, error) {
	var s Settings
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, fmt.Errorf("the source's settings: %w", err)
	}
	if d.More() {
		return s, errors.New("the source's settings: trailing data")
	}
	if s.V != 1 {
		return s, fmt.Errorf("the source's settings: version %d", s.V)
	}
	if !sessionIDRE.MatchString(s.Session) {
		return s, fmt.Errorf("the source's settings: session %q", s.Session)
	}
	switch {
	case s.Harness == "claude" || s.Harness == "opencode" || s.Harness == "openclaw":
	case strings.HasPrefix(s.Harness, taskHarnessPrefix) && taskTemplateRE.MatchString(strings.TrimPrefix(s.Harness, taskHarnessPrefix)):
	default:
		return s, fmt.Errorf("the source's settings: harness %q", s.Harness)
	}
	if s.PermissionMode != "auto" && s.PermissionMode != "bypass" {
		return s, fmt.Errorf("the source's settings: permission mode %q", s.PermissionMode)
	}
	if s.Model != "" && !modelRE.MatchString(s.Model) {
		return s, fmt.Errorf("the source's settings: model %q", s.Model)
	}
	for _, r := range s.Repos {
		if rp := repoOfURL(r); !ghRepoRE.MatchString(rp) || strings.HasSuffix(rp, "/.") || strings.HasSuffix(rp, "/..") || !validRepo(rp) {
			return s, fmt.Errorf("the source's settings: repo %q isn't a GitHub repo", r)
		}
	}
	for _, n := range s.Content {
		if !contentRE.MatchString(n) {
			return s, fmt.Errorf("the source's settings: content store %q", n)
		}
	}
	for _, a := range s.Attachments {
		if !plainName(a.Name) || !sha256RE.MatchString(a.Sha256) || a.Size < 0 {
			return s, fmt.Errorf("the source's settings: attachment %q", a.Name)
		}
	}
	if s.Rollback != "" && len(s.Rollback) < 4 {
		return s, errors.New("the source's settings: rollback marker too short")
	}
	if t := s.Task; t != nil && t.Instance != "" && !taskTemplateRE.MatchString(t.Instance) {
		return s, errors.New("the source's settings: task instance")
	}
	return s, nil
}

// repoOfURL: owner/name of a GitHub https or ssh URL, or an owner/name itself ("" otherwise)
func repoOfURL(u string) string {
	u = strings.TrimSpace(u)
	for _, p := range []string{"https://github.com/", "git@github.com:", "ssh://git@github.com/"} {
		if rest, ok := strings.CutPrefix(u, p); ok {
			return strings.TrimSuffix(strings.TrimSuffix(rest, "/"), ".git")
		}
	}
	if !strings.Contains(u, ":") {
		return strings.TrimSuffix(u, ".git")
	}
	return ""
}

// reposToClone: the settings' repos, or, when they name none, each repo whose deploy-key store the grant gave this
// machine (the store names the repo). Never the router's list.
func reposToClone(s Settings, secrets map[string]string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(repo string) {
		if ghRepoRE.MatchString(repo) && validRepo(repo) && !seen[strings.ToLower(repo)] {
			seen[strings.ToLower(repo)] = true
			out = append(out, "https://github.com/"+repo+".git")
		}
	}
	if len(s.Repos) > 0 {
		for _, r := range s.Repos {
			add(repoOfURL(r))
		}
		return out
	}
	for _, k := range deployKeys(secrets) {
		add(k.Repo)
	}
	return out
}

// ---- values the router may give on its own (their format can't carry an instruction) -----------------------

// FormatExceptions: GET /m/config (docs/API-grants.md). Anything else in the answer is ignored.
type FormatExceptions struct {
	DiscordChannel  string `json:"discordChannel"`  // a Discord channel id: digits
	LiveSyncSeconds int    `json:"liveSyncSeconds"` // how often the transcripts go to the search index
	TaskRun         string `json:"taskRun"`         // the run a task line's machine is started for: an id
	TaskTrigger     string `json:"taskTrigger"`     // what started it: a word
	TunnelProof     string `json:"tunnelProof"`     // the router's proof for the cf-tunnel Worker: a token
}

var (
	sessionIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	digitsRE    = regexp.MustCompile(`^[0-9]{1,32}$`)
	wordRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	tokenRE     = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{1,512}$`)
)

// checkExceptions: each value in its format, or dropped
func checkExceptions(in FormatExceptions) FormatExceptions {
	out := FormatExceptions{}
	if digitsRE.MatchString(in.DiscordChannel) {
		out.DiscordChannel = in.DiscordChannel
	}
	if in.LiveSyncSeconds >= 5 && in.LiveSyncSeconds <= 86400 {
		out.LiveSyncSeconds = in.LiveSyncSeconds
	}
	if sessionIDRE.MatchString(in.TaskRun) {
		out.TaskRun = in.TaskRun
	}
	if wordRE.MatchString(in.TaskTrigger) {
		out.TaskTrigger = in.TaskTrigger
	}
	if tokenRE.MatchString(in.TunnelProof) {
		out.TunnelProof = in.TunnelProof
	}
	return out
}

func fetchExceptions(c *client) FormatExceptions {
	var ex FormatExceptions
	if err := c.json("GET", "/m/config", nil, &ex); err != nil {
		log.Printf("config: none from the router (%v)", err)
	}
	if ex.TunnelProof == "" {
		ex.TunnelProof = tunnelProof(c) // tunnelproof.go
	}
	return checkExceptions(ex)
}

// ---- the harness's env, built from the settings, the secrets and the format exceptions only ----------------------

// harnessEnv: the clean env plus exactly what the settings, the secrets and the format exceptions give. fromPhone: the
// source was made by the phone (out of the sink): its prompt is typed at the start.
func harnessEnv(clean []string, s Settings, ex FormatExceptions, fromPhone bool, secretsJSON string, secrets map[string]string) []string {
	m := map[string]string{}
	for _, kv := range clean {
		if k, val, ok := strings.Cut(kv, "="); ok {
			m[k] = val
		}
	}
	sid := s.Session
	m["SESSION_SECRETS_JSON"] = secretsJSON
	m["SESSION_HARNESS"], m["SESSION_PERMISSION_MODE"] = s.Harness, s.PermissionMode
	m["SESSION_ID"], m["JARVIS2_SESSION_ID"], m["TUNNEL_ID"] = sid, sid, sid
	m["JARVIS_URL"], m["SESSION_API_TOKEN"] = "http://"+apiProxyAddr, "jarvis2-local-proxy"
	if s.Harness != "opencode" && s.Harness != "openclaw" {
		// Jarvis 1's scripts insist on these before calling the local API; OpenCode/OpenClaw take them as "publish
		// the web UI through the tunnel"
		m["CF_ACCESS_CLIENT_ID"], m["CF_ACCESS_CLIENT_SECRET"] = "jarvis2-local-proxy", "jarvis2-local-proxy"
	}
	if ex.DiscordChannel != "" {
		m["LOBSTER_CHANNEL"] = ex.DiscordChannel
	}
	if ex.TunnelProof != "" {
		m["TUNNEL_AGENT_SECRET"] = ex.TunnelProof
	}
	for _, k := range []string{"CLAUDE_CREDENTIALS", "CLAUDE_ACCOUNT"} {
		if v := secrets[k]; v != "" {
			m[k] = v
		}
	}
	if s.Title != "" {
		m["SESSION_LABEL"] = s.Title
	}
	if s.Model != "" {
		m["SESSION_MODEL"] = s.Model
	}
	if s.OneShot {
		m["SESSION_ONE_SHOT"] = "1"
	}
	if s.APIProxy {
		m["SESSION_API_PROXY"] = "1"
	}
	if len(s.Content) > 0 {
		m["SESSION_CONTENT"] = strings.Join(s.Content, ",")
	}
	if fromPhone && s.Prompt != "" {
		m["SESSION_PROMPT"] = s.Prompt
	}
	out := make([]string, 0, len(m))
	for k, val := range m {
		out = append(out, k+"="+val)
	}
	sort.Strings(out)
	return out
}

// taskEnv: a task line's values for task.go (which reads TASK_* / PARAM_* from the process env): the instance and its
// parameters from the settings, the run id and trigger as format exceptions
func taskEnv(s Settings, ex FormatExceptions) []string {
	sid := s.Session
	out := []string{"SESSION_ID=" + sid, "JARVIS2_SESSION_ID=" + sid, "JARVIS_URL=http://" + apiProxyAddr, "SESSION_API_TOKEN=jarvis2-local-proxy"}
	if ex.DiscordChannel != "" {
		out = append(out, "LOBSTER_CHANNEL="+ex.DiscordChannel)
	}
	if ex.TaskRun != "" {
		out = append(out, "JARVIS2_TASK_RUN="+ex.TaskRun, "TASK_RUN="+ex.TaskRun, "TASK_TRIGGER="+ex.TaskTrigger)
	}
	t := s.Task
	if t == nil {
		return append(out, "TASK_PARAMS={}")
	}
	pj, _ := json.Marshal(t.Params)
	out = append(out, "TASK_INSTANCE="+t.Instance, "TASK_NAME="+t.Name, "TASK_PARAMS="+string(pj))
	for k, val := range t.Params {
		name := "PARAM_" + strings.ToUpper(k)
		if envNameRE.MatchString(name) {
			out = append(out, name+"="+paramValue(val))
		}
	}
	return out
}

// paramValue: router/tasks.go paramEnv
func paramValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []any:
		parts := []string{}
		for _, e := range x {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, ",")
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case string:
		return x
	}
	b, _ := json.Marshal(v)
	return string(b)
}
