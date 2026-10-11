#!/usr/bin/env python3
"""The phone replica's host helper (replica.yml): what a person and the setup session do around the phone, served to
the UI test (ReplicaUITests) on 127.0.0.1:18300.

  GET /faceid/match?for=N   Face ID matches for the next N seconds (each prompt that appears is matched)
  GET /faceid/nomatch       the next prompt fails (a face that isn't enrolled)
  GET /relay?msg=M          M to the setup session (infra/phone-replica.sh) through the piping relay; its answer back
  GET /log?msg=M            a line in this helper's log
  GET /ext/kill             SIGKILL the React Native extension's process (JarvisUI), as iOS ends it under memory
                            pressure or in the background
  GET /ext/stop?for=N       SIGSTOP it for N seconds, then SIGCONT (an extension that is slow to come back)
  GET /memwarn              the simulator's memory warning (Debug → Simulate Memory Warning)

  (transitions.yml runs it too, with RELAY_URL "-": no relay there)

  replica-host.py UDID RELAY_URL     (RELAY_URL: https://ppng.io/<random>; /req and /resp under it)
"""
import http.server, subprocess, sys, threading, time, urllib.parse, urllib.request

UDID, RELAY = sys.argv[1], sys.argv[2].rstrip("/")
state = {"until": 0.0, "fail": False}
lock = threading.Lock()


def notify(name):
    subprocess.run(["xcrun", "simctl", "spawn", UDID, "notifyutil", "-p", f"com.apple.BiometricKit_Sim.{name}"], check=False)


def matcher():
    while True:
        time.sleep(1.5)
        with lock:
            fail, until = state["fail"], state["until"]
            if fail:
                state["fail"] = False
        if fail:
            for _ in range(3):        # the prompt shows a moment after the tap
                notify("pearl.nomatch")
                time.sleep(1.5)
        elif time.time() < until:
            notify("pearl.match")


def ext_pids():
    r = subprocess.run(["pgrep", "-x", "JarvisUI"], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split()]


def signal_ext(sig):
    pids = ext_pids()
    for p in pids:
        subprocess.run(["kill", f"-{sig}", str(p)], check=False)
    return pids


def relay(msg):
    req = urllib.request.Request(RELAY + "/req", data=msg.encode(), method="POST")
    urllib.request.urlopen(req, timeout=600).read()
    return urllib.request.urlopen(RELAY + "/resp", timeout=900).read().decode()


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        out = "ok"
        if u.path == "/faceid/match":
            with lock:
                state["until"], state["fail"] = time.time() + float(q.get("for", "40")), False
        elif u.path == "/faceid/nomatch":
            with lock:
                state["until"], state["fail"] = 0, True
        elif u.path == "/relay":
            print(f"relay → {q.get('msg')}", flush=True)
            try:
                out = relay(q.get("msg", ""))
            except Exception as e:
                out = f"relay failed: {e}"
            print(f"relay ← {len(out)} chars", flush=True)
        elif u.path == "/ext/kill":
            out = f"killed {signal_ext('KILL')}"
            print(out, flush=True)
        elif u.path == "/ext/stop":
            secs = float(q.get("for", "4"))
            out = f"stopped {signal_ext('STOP')} for {secs}s"
            print(out, flush=True)
            threading.Timer(secs, lambda: print(f"continued {signal_ext('CONT')}", flush=True)).start()
        elif u.path == "/memwarn":
            subprocess.run(["xcrun", "simctl", "spawn", UDID, "notifyutil", "-p", "com.apple.UIKit.SimulatorMemoryWarning"], check=False)
        elif u.path == "/log":
            print(q.get("msg", ""), flush=True)
        else:
            self.send_response(404); self.end_headers(); return
        b = out.encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def log_message(self, f, *a):
        print(time.strftime("%H:%M:%S"), self.path.split("?")[0], flush=True)


threading.Thread(target=matcher, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", 18300), H).serve_forever()
