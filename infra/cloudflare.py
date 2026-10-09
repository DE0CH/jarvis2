#!/usr/bin/env python3
"""Cloudflare side of Jarvis 2 (idempotent): the tunnel, its DNS name, the two Access apps, the setup
session's service token. Writes TUNNEL_TOKEN (for the box) and SETUP_ACCESS_ID/SECRET (for the setup
session, Jarvis 1's default store as JARVIS2_SETUP_ACCESS_ID/SECRET) to OUT (mode 600); prints nothing secret.
The apps' audiences are not secret: they are in k8s/apps/router.yaml (the script prints them to check).

  CF_JARVIS2_INFRA_TOKEN  tunnel + Access apps + DNS (scoped token "jarvis2-infra")
  CLOUDFLARE_API          only to mint the setup service token (the scoped token can't)

  infra/cloudflare.py OUT
Access apps (created Access first, then DNS, so the hostname is never reachable ungated):
  "Jarvis 2"        jarvis2.deyaochen.com         Deyao's email only (the app + web page)
  "Jarvis 2 setup"  jarvis2.deyaochen.com/setup   service token jarvis2-setup only (the setup session)
Session machines don't come through Cloudflare at all (Fly's private network, docs/API.md).
"""
import json, os, sys, urllib.request, urllib.error

ACCOUNT = "ee3b4deef856baf11e1a67b242438325"
ZONE = "f51ca95ee5e6c664372000f887c96a92"
HOST = "jarvis2.deyaochen.com"
EMAIL = "chendeyao000@gmail.com"
ORIGIN = "http://router.jarvis2-router.svc.cluster.local:8080"
API = "https://api.cloudflare.com/client/v4"


def call(method, path, body=None, token=None):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + (token or os.environ["CF_JARVIS2_INFRA_TOKEN"]),
                                          "Content-Type": "application/json", "User-Agent": "jarvis2-infra/1"})
    try:
        r = json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        r = json.loads(e.read() or b"{}")
    if not r.get("success"):
        raise SystemExit(f"{method} {path}: {r.get('errors')}")
    return r["result"]


def access_app(name, domain, policy):
    apps = call("GET", f"/accounts/{ACCOUNT}/access/apps")
    app = next((a for a in apps if a.get("domain") == domain), None)
    body = {"name": name, "domain": domain, "type": "self_hosted", "session_duration": "720h",
            "app_launcher_visible": False, "auto_redirect_to_identity": False}
    app = call("PUT" if app else "POST", f"/accounts/{ACCOUNT}/access/apps" + (f"/{app['id']}" if app else ""), body)
    pols = call("GET", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies")
    for p in pols:
        call("DELETE", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies/{p['id']}")
    call("POST", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies", dict(policy, precedence=1))
    return app["aud"]


def main():
    out = sys.argv[1]
    vals = {}

    # 1. the setup session's service token (needs the broader token; kept unless ROTATE=1)
    toks = call("GET", f"/accounts/{ACCOUNT}/access/service_tokens", token=os.environ["CLOUDFLARE_API"])
    tok = next((t for t in toks if t["name"] == "jarvis2-setup"), None)
    prev = {}
    if os.path.exists(out):
        prev = dict(l.rstrip("\n").split("=", 1) for l in open(out) if "=" in l)
    if tok and not os.environ.get("ROTATE") and prev.get("SETUP_ACCESS_SECRET"):
        vals["SETUP_ACCESS_ID"], vals["SETUP_ACCESS_SECRET"] = prev["SETUP_ACCESS_ID"], prev["SETUP_ACCESS_SECRET"]
        tok_id = tok["id"]
    else:
        if tok:
            call("DELETE", f"/accounts/{ACCOUNT}/access/service_tokens/{tok['id']}", token=os.environ["CLOUDFLARE_API"])
        t = call("POST", f"/accounts/{ACCOUNT}/access/service_tokens", {"name": "jarvis2-setup", "duration": "8760h"},
                 token=os.environ["CLOUDFLARE_API"])
        vals["SETUP_ACCESS_ID"], vals["SETUP_ACCESS_SECRET"], tok_id = t["client_id"], t["client_secret"], t["id"]

    # 2. Access apps first
    aud = access_app("Jarvis 2", HOST, {"name": "Deyao", "decision": "allow", "include": [{"email": {"email": EMAIL}}]})
    setup_aud = access_app("Jarvis 2 setup", HOST + "/setup", {
        "name": "setup session", "decision": "non_identity", "include": [{"service_token": {"token_id": tok_id}}]})
    print(f"audiences (k8s/apps/router.yaml): ACCESS_APP_AUD={aud} ACCESS_SETUP_AUD={setup_aud}")

    # 3. the tunnel (remotely managed) and its ingress
    tunnels = call("GET", f"/accounts/{ACCOUNT}/cfd_tunnel?name=jarvis2&is_deleted=false")
    tun = tunnels[0] if tunnels else call("POST", f"/accounts/{ACCOUNT}/cfd_tunnel", {"name": "jarvis2", "config_src": "cloudflare"})
    call("PUT", f"/accounts/{ACCOUNT}/cfd_tunnel/{tun['id']}/configurations", {"config": {"ingress": [
        {"hostname": HOST, "service": ORIGIN}, {"service": "http_status:404"}]}})
    vals["TUNNEL_TOKEN"] = call("GET", f"/accounts/{ACCOUNT}/cfd_tunnel/{tun['id']}/token")

    # 4. DNS last
    recs = call("GET", f"/zones/{ZONE}/dns_records?name={HOST}")
    rec = {"type": "CNAME", "name": HOST, "content": f"{tun['id']}.cfargotunnel.com", "proxied": True, "comment": "Jarvis 2 tunnel"}
    if recs:
        call("PUT", f"/zones/{ZONE}/dns_records/{recs[0]['id']}", rec)
    else:
        call("POST", f"/zones/{ZONE}/dns_records", rec)

    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for k, v in vals.items():
            f.write(f"{k}={v}\n")
    print(f"ok: tunnel {tun['id']}, Access apps + setup service token ready; values in {out}")


if __name__ == "__main__":
    main()
