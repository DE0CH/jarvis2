# Jarvis 2 — runbook

Everything here runs from a Claude session whose env has the `default` store (JARVIS2_* keys, CF tokens,
HETZNER_JARVIS2_MOCK_API). The box's admin kubeconfig is written by `infra/setup.py` from
`JARVIS2_K8S_ADMIN_TOKEN` + `JARVIS2_BOX_IP` into `~/.jarvis2/kubeconfig`.

## Deploying

`git push` to main. The `images` workflow builds core / router / session images, then pins their tags in
`k8s/apps/`; Flux applies within a minute. The core's tag moves only when `core/` changed (a core restart is a
new controller: see "Initialising a core").

## Initialising a core (after a box rebuild or any core restart)

1. `infra/setup.py fly` — the core gets the Fly token.
2. `infra/setup.py core-key` — send Deyao the `jarvis2-core:…` string; he pastes it into the app's pairing
   page. The app shows `jarvis2-phone:…`; he sends it back.
3. `infra/setup.py phone 'jarvis2-phone:…'` — once per core.
4. `infra/setup.py seed <store> KEY… [--sensitive]` for each store Deyao wants (values from this session's
   env, never printed). `infra/setup.py stores` lists them.
5. Deyao unlocks the stores in the app when a session needs them.

## Rebuilding the box

1. Delete the server in the jarvis2 Hetzner project (API or console).
2. `infra/cloudflare.py ~/.jarvis2/cloudflare.env` (with `ROTATE=1` if that file is gone: a new machines'
   service token; put the new values in the `default` store as JARVIS2_MACHINE_ACCESS_ID/SECRET).
3. `infra/create.sh` (needs `~/.jarvis2/k8s-admin-token` and `~/.jarvis2/ssh`: write them from
   JARVIS2_K8S_ADMIN_TOKEN / JARVIS2_SSH_KEY first, so the stored ones keep working; it creates new ones
   otherwise — store those). Then update JARVIS2_BOX_IP.
4. Initialise the core (above). Paused sessions are lost with a core restart (their certs were signed by
   the old core).

## Testing

- Unit: `go test ./...` in core/, router/, machine/.
- End to end on real Fly with a software phone: `e2e/` (its header says how). It sets the phone key on the
  core, so run it on a fresh core (`kubectl -n jarvis2-core rollout restart deploy/core`) with Flux
  suspended and the router in `NO_ACCESS=1`, then restart the core again afterwards and re-run
  "Initialising a core". Passed 2026-10-08.

## Looking at things

- `kubectl --kubeconfig ~/.jarvis2/kubeconfig get pods -A`
- Core log (setup token, every primitive): `kubectl -n jarvis2-core logs deploy/core`
- A session machine's log: `FLY_API_TOKEN=$JARVIS2_FLY_TOKEN flyctl logs -a jarvis2-sessions --machine <id> --no-tail`
