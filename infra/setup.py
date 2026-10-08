#!/usr/bin/env python3
"""Initialise a fresh Jarvis 2 core (PLAN "Initialisation"), run by the trusted setup session. It reaches the
core through `kubectl port-forward` with the box's admin kubeconfig (~/.jarvis2/kubeconfig, or written from
JARVIS2_K8S_ADMIN_TOKEN + JARVIS2_BOX_IP) and reads the one-time setup token from the core's log. Values
never print.

  infra/setup.py fly                         give the core the Fly token (JARVIS2_FLY_TOKEN, app jarvis2-sessions)
  infra/setup.py core-key                    the string Deyao pastes into the app: jarvis2-core:<signing>:<agreement>
  infra/setup.py phone 'jarvis2-phone:…'     the phone's keys, from the app's pairing page (once per core)
  infra/setup.py seed NAME KEY [KEY…] [--sensitive]
                                             a new store with those keys' values from this session's env
  infra/setup.py stores                      the core's (signed) store list, names and key names only
"""
import json, os, socket, subprocess, sys, time, urllib.request, urllib.error

D = os.path.expanduser("~/.jarvis2")


def kubeconfig():
    p = os.path.join(D, "kubeconfig")
    if not os.path.exists(p):
        os.makedirs(D, mode=0o700, exist_ok=True)
        tok, ip = os.environ["JARVIS2_K8S_ADMIN_TOKEN"], os.environ["JARVIS2_BOX_IP"]
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"""apiVersion: v1
kind: Config
clusters: [{{name: jarvis2, cluster: {{server: "https://{ip}:6443", insecure-skip-tls-verify: true}}}}]
users: [{{name: admin, user: {{token: "{tok}"}}}}]
contexts: [{{name: jarvis2, context: {{cluster: jarvis2, user: admin}}}}]
current-context: jarvis2
""")
    return p


def kubectl(*args):
    return subprocess.run(["kubectl", "--kubeconfig", kubeconfig(), *args], capture_output=True, text=True, check=True).stdout


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Core:
    def __enter__(self):
        self.port = free_port()
        self.pf = subprocess.Popen(["kubectl", "--kubeconfig", kubeconfig(), "-n", "jarvis2-core", "port-forward", "deploy/core",
                                    f"{self.port}:8090"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close(); break
            except OSError:
                time.sleep(0.2)
        logs = kubectl("-n", "jarvis2-core", "logs", "deploy/core")
        self.token = next(l.split("SETUP TOKEN ")[1].strip() for l in logs.splitlines() if "SETUP TOKEN " in l)
        return self

    def __exit__(self, *a):
        self.pf.terminate()

    def call(self, method, path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", "X-Setup-Token": self.token})
        try:
            return json.load(urllib.request.urlopen(req))
        except urllib.error.HTTPError as e:
            d = json.loads(e.read() or b"{}")
            msg = json.loads(d.get("payload", "{}")).get("error") if "payload" in d else d
            raise SystemExit(f"core {path}: HTTP {e.code}: {msg}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    with Core() as c:
        if cmd == "core-key":
            k = c.call("GET", "/key")
            print(f"jarvis2-core:{k['signingKey']}:{k['agreementKey']}")
        elif cmd == "fly":
            c.call("POST", "/setup/fly", {"token": os.environ["JARVIS2_FLY_TOKEN"], "app": os.environ.get("JARVIS2_FLY_APP", "jarvis2-sessions")})
            print("ok: the core holds the Fly token")
        elif cmd == "phone":
            parts = args[0].strip().split(":")
            if len(parts) != 3 or parts[0] != "jarvis2-phone":
                raise SystemExit("expected jarvis2-phone:<signingKey>:<agreementKey>")
            c.call("POST", "/setup/phone", {"signingKey": parts[1], "agreementKey": parts[2]})
            print("ok: phone keys set")
        elif cmd == "seed":
            sens = "--sensitive" in args
            args = [a for a in args if a != "--sensitive"]
            name, keys = args[0], args[1:]
            missing = [k for k in keys if k not in os.environ]
            if missing:
                raise SystemExit(f"not in this session's env: {missing}")
            c.call("POST", "/setup/store", {"name": name, "values": {k: os.environ[k] for k in keys}, "sensitive": sens})
            print(f"ok: store {name} seeded with {len(keys)} keys (sensitive={sens})")
        elif cmd == "stores":
            d = c.call("POST", "/stores", {"nonce": "setup"})
            for s in json.loads(d["payload"])["stores"]:
                print(s["name"], "sensitive" if s["sensitive"] else "", "unlocked" if s["unlocked"] else "locked", ",".join(s["keys"]))
        else:
            raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
