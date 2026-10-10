Public keys Jarvis 2 trusts (docs/DESIGN.md):
- `master.pub` — the master key. Made on Deyao's iPhone, which shows only this public half; the private half
  stays there until it goes into his recovery kit (the one string in his password manager). Signs recovery;
  built into the session image; the core's manifest carries it as MASTER_KEY.
- `box.pub` — the box key (private half only on the box, from user-data at creation). Signs each core's
  identity; the app's recovery page checks it. A new box = a new key (infra/create.sh writes this file).
- `setup.pub` — the setup session's key (private half JARVIS2_SETUP_KEY in Jarvis 1's default store). The
  router checks it on every /setup call; the app checks it on the backups the setup session writes.
