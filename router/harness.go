package main

// The harnesses and their models (Jarvis 1's MODELS / HARNESSES in selfhost/jarvis/server.js). A model belongs to
// one harness: the New-session request carries both; the harness is signed (the cert's options, SESSION_HARNESS on
// the machine), the model is not (SESSION_MODEL in the machine env, read by the harness script):
//   claude    Claude Code on the Claude subscription (`claude --model <id>`), the Claude app
//   opencode  OpenCode on OpenRouter (`openrouter/<slug>`), driven by a Paseo daemon: the Paseo app + web UI
//   openclaw  claw-code inside an OpenClaw gateway (`openclaw/<Claude model id>`), Claude subscription: the
//             OpenClaw app + Control UI
// The OpenCode list is Jarvis 1's curated one (every slug checked for tool calling on OpenRouter; prices are $/M
// tokens in/out at curation).

import (
	"fmt"
	"net/http"
)

type ModelChoice struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Harness string `json:"harness"`
}

var modelCatalog = []ModelChoice{
	{"claude-opus-5-5", "Opus 5.5", "claude"},
	{"claude-fable-5-1", "Fable 5.1", "claude"},
	{"openrouter/z-ai/glm-5.3", "GLM 5.3 — $0.90 / $2.82", "opencode"},
	{"openrouter/moonshotai/kimi-k3", "Kimi K3 — $1.70 / $8.50", "opencode"},
	{"openrouter/deepseek/deepseek-v4-pro-0813", "DeepSeek V4 Pro — $0.66 / $1.98", "opencode"},
	{"openrouter/deepseek/deepseek-v4.1-flash", "DeepSeek V4.1 Flash — $0.15 / $0.60", "opencode"},
	{"openrouter/qwen/qwen3-coder-next", "Qwen3 Coder Next — $0.12 / $0.80", "opencode"},
	{"openrouter/minimax/minimax-m3", "MiniMax M3 — $0.30 / $1.20", "opencode"},
	{"openclaw/claude-opus-5-5", "Opus 5.5", "openclaw"},
	{"openclaw/claude-fable-5-1", "Fable 5.1", "openclaw"},
}

// the first model of each harness is its default
var harnessInfo = map[string]map[string]string{
	"claude":   {"label": "Claude Code", "detail": "Claude subscription · Claude app"},
	"opencode": {"label": "OpenCode · OpenRouter", "detail": "Paseo app + web UI"},
	"openclaw": {"label": "claw-code · OpenClaw", "detail": "Claude subscription · OpenClaw app + Control UI"},
}

func defaultModel(harness string) string {
	for _, m := range modelCatalog {
		if m.Harness == harness {
			return m.ID
		}
	}
	return ""
}

// sessionModel: the model a new session of this harness runs. Empty, or another harness's model (the iPhone shell
// picks the harness after the form picked a model), → the harness's default; an id that isn't in the list is
// refused, as in Jarvis 1, so a typo can't start a session on a model that doesn't exist.
func sessionModel(harness, model string) (string, error) {
	if model == "" {
		return defaultModel(harness), nil
	}
	for _, m := range modelCatalog {
		if m.ID == model {
			if m.Harness != harness {
				return defaultModel(harness), nil
			}
			return model, nil
		}
	}
	return "", fmt.Errorf("unknown model %q (GET /api/models lists them)", model)
}

// GET /api/models[?harness=x] → {models: [{id, label, harness}], default, defaults: {harness: id}, harnesses}
func (r *Router) registerHarnesses(app appRoute) {
	app("GET /api/models", func(w http.ResponseWriter, req *http.Request) {
		h := req.URL.Query().Get("harness")
		out := []ModelChoice{}
		for _, m := range modelCatalog {
			if _, ok := r.policy.Harnesses[m.Harness]; !ok && len(r.policy.Harnesses) > 0 {
				continue // a harness the policy doesn't offer
			}
			if h == "" || m.Harness == h {
				out = append(out, m)
			}
		}
		defaults, harnesses := map[string]string{}, map[string]map[string]string{}
		for name, info := range harnessInfo {
			if _, ok := r.policy.Harnesses[name]; ok || len(r.policy.Harnesses) == 0 {
				defaults[name], harnesses[name] = defaultModel(name), info
			}
		}
		def := defaultModel("claude")
		if h != "" {
			def = defaultModel(h)
		}
		writeJSON(w, 200, map[string]any{"models": out, "default": def, "defaults": defaults, "harnesses": harnesses})
	})
}
