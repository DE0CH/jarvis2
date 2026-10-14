#!/usr/bin/env python3
"""CI only (kernel-up.sh): the box's roster names the app's phone and root keys, which exist only once the app has made
them. On the box the setup session puts them in after Deyao's Reset or Recover (infra/setup.py claim-keys |
infra/kernel-keys.py from-claim, then the parts restart). Here this does the same, every second: once the router keeps
a claim for the running secrets whose keys differ from W/roster.json, it writes them there and starts every part but
secrets again (parts.sh) so they read the new roster. Secrets isn't restarted: it takes no phone or root signature from
the roster, and a restart would empty it.
usage: roster-watch.py W LOGDIR TAG"""
import json, os, subprocess, sys, time

W, LOGS, TAG = sys.argv[1:4]
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PY = sys.executable
env = dict(os.environ, JARVIS2_URL="http://127.0.0.1:18080", JARVIS2_KEYS_DIR=os.path.join(W, "keys"),
           JARVIS2_SETUP_KEY=open(os.path.join(W, "setup-key.pem")).read(),
           JARVIS2_SETUP_ACCESS_ID="ci", JARVIS2_SETUP_ACCESS_SECRET="ci")
roster = os.path.join(W, "roster.json")
last_err = ""
while True:
    p = subprocess.run([PY, "-B", os.path.join(ROOT, "infra", "setup.py"), "claim-keys"], env=env, capture_output=True, text=True)
    if p.returncode == 0:
        try:
            c = json.loads(p.stdout)
        except ValueError:
            c = {}
        r = json.load(open(roster))
        if c.get("phone") and c.get("root") and (r.get("phone"), r.get("root")) != (c["phone"], c["root"]):
            q = subprocess.run([PY, "-B", os.path.join(ROOT, "infra", "kernel-keys.py"), "--roster", roster, "from-claim"],
                               input=p.stdout, capture_output=True, text=True)
            print(time.strftime("%H:%M:%S"), q.stdout.strip(), q.stderr.strip(), flush=True)
            if q.returncode == 0:
                subprocess.run(["bash", os.path.join(ROOT, "ios", "ci", "parts.sh"), W, LOGS, TAG], check=False)
                print(time.strftime("%H:%M:%S"), "parts restarted on the new roster", flush=True)
        elif not (c.get("phone") and c.get("root")):
            print(time.strftime("%H:%M:%S"), "claim without phone/root:", p.stdout.strip(), flush=True)
    else:
        err = (p.stderr.strip().splitlines() or [""])[-1]
        if err != last_err:  # "secrets is empty" until the app claims it
            print(time.strftime("%H:%M:%S"), "no claim yet:", err, flush=True)
            last_err = err
    time.sleep(1)
