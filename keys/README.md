Public keys Jarvis 2 trusts (docs/DESIGN.md):
- `box.pub` — the box key (private half only on the box, from user-data at creation). Signs each core's
  identity; the app and `infra/setup.py` check it before they trust a core. A new box = a new key
  (infra/create.sh writes this file).
- `box-age.pub` — the box's age key: the SOPS recipient of the router's secrets (k8s/secrets/).
- `setup.pub` — the setup session's key (private half JARVIS2_SETUP_KEY in Jarvis 1's default store). The
  router checks it on every /setup call; the app checks it on the backups the setup session writes.

No master key is here: Deyao's app makes it (Reset), its private half exists only in his recovery kit, and the
core learns the public half from his claim.
