#!/usr/bin/env python3
"""grafana.py — Jarvis 2's alerting in Grafana Cloud, as code (docs/RUNBOOK.md "Logs, metrics and alerts").

    GRAFANA_ADMIN_TOKEN=… GRAFANA_DISCORD_WEBHOOK=… infra/grafana.py apply [--boxes control,services]
    GRAFANA_ADMIN_TOKEN=… infra/grafana.py show
    GRAFANA_SM_TOKEN=… HEALTH_PROBE_ID=… HEALTH_PROBE_SECRET=… infra/grafana.py probe

Stack jumboshortbread1389 (EU Germany, prod-eu-west-2). GRAFANA_ADMIN_TOKEN is the stack's service account token
`jarvis2-admin`; GRAFANA_DISCORD_WEBHOOK is the webhook "Grafana" of the Discord channel #jarvis2-alerts (both in the
`infra` store). `apply` makes or updates, idempotently: the contact point (Discord), the notification policy (every
alert to it), the folder "Jarvis 2" and the rule group "boxes" below, for the boxes named (a box that doesn't exist
yet would fire "silent"). The rules read what Alloy ships from each box (infra/alloy/box.alloy) and what the external
probe reports (Synthetic Monitoring, `probe` below). Prints names, never a token.

`probe` makes or updates the Synthetic Monitoring HTTP check `jarvis2-healthz`: GET https://jarvis2.deyaochen.com/healthz
once a minute from London and Frankfurt (2 × 43,200 = 86,400 runs a month, inside the free 100k), with the Access
service token jarvis2-health-probe (infra/cloudflare.py --health), 200 required. GRAFANA_SM_TOKEN is the Synthetic
Monitoring access token of the stack (`infra` store).
"""
SM = "https://synthetic-monitoring-api-eu-west-2.grafana.net/api/v1"
import json, os, sys, urllib.request, urllib.error

STACK = "https://jumboshortbread1389.grafana.net"
PROM, LOKI = "grafanacloud-prom", "grafanacloud-logs"
FOLDER = "jarvis2"


def call(method, path, body=None):
    req = urllib.request.Request(STACK + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + os.environ["GRAFANA_ADMIN_TOKEN"],
                                          "Content-Type": "application/json", "X-Disable-Provenance": "true",
                                          "User-Agent": "jarvis2-infra"})
    try:
        with urllib.request.urlopen(req) as r:
            t = r.read()
            return r.status, json.loads(t) if t else {}
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]


def rule(uid, title, summary, ds, expr, threshold, for_="2m", kind="prom", severity="warning"):
    """one alert rule: query A, reduce B (last), threshold C (> threshold)"""
    model = {"refId": "A", "expr": expr, "instant": True} if kind == "prom" else {"refId": "A", "expr": expr, "queryType": "instant"}
    return {
        "uid": uid, "title": title, "condition": "C", "for": for_, "noDataState": "OK", "execErrState": "Error",
        "annotations": {"summary": summary}, "labels": {"severity": severity, "system": "jarvis2"},
        "data": [
            {"refId": "A", "datasourceUid": ds, "relativeTimeRange": {"from": 600, "to": 0}, "model": model},
            {"refId": "B", "datasourceUid": "__expr__", "relativeTimeRange": {"from": 0, "to": 0},
             "model": {"refId": "B", "type": "reduce", "expression": "A", "reducer": "last"}},
            {"refId": "C", "datasourceUid": "__expr__", "relativeTimeRange": {"from": 0, "to": 0},
             "model": {"refId": "C", "type": "threshold", "expression": "B",
                       "conditions": [{"evaluator": {"type": "gt", "params": [threshold]}}]}},
        ],
    }


def rules(boxes):
    r = [
        # memory pressure: the share of time every task stalled on memory (PSI "full"), the warning before a thrash
        rule("j2-mem-pressure", "Memory pressure on {{ $labels.box }}",
             "PSI memory full above 2 % for 2 min on the {{ $labels.box }} box: something is starving it (2026-10-15 started like this)",
             PROM, 'sum by (box) (rate(node_pressure_memory_stalled_seconds_total{box=~"control|services"}[2m]))', 0.02),
        rule("j2-oom", "OOM kill on {{ $labels.box }}",
             "The kernel killed a process for memory on the {{ $labels.box }} box in the last 5 min (journal: unit kernel)",
             PROM, 'sum by (box) (increase(node_vmstat_oom_kill{box=~"control|services"}[5m]))', 0, for_="0s"),
        rule("j2-disk", "Disk above 80 % on {{ $labels.box }}",
             "The root filesystem of the {{ $labels.box }} box is over 80 % full",
             PROM, 'max by (box) (1 - node_filesystem_avail_bytes{box=~"control|services",mountpoint="/"} / node_filesystem_size_bytes{box=~"control|services",mountpoint="/"})', 0.8, for_="10m"),
        rule("j2-flux", "Flux failing on {{ $labels.box }}",
             "Flux on the {{ $labels.box }} box has failed to reconcile for 10 min: a commit isn't reaching it (its logs: container manager)",
             LOKI, 'sum by (box) (count_over_time({box=~"control|services", container="manager"} |~ "(?i)reconciliation failed" [10m]))', 5, for_="10m", kind="loki"),
        rule("j2-restarts", "Control plane restarting on {{ $labels.box }}",
             "A control-plane container (core, router, cloudflared) was restarted by the kubelet in the last 10 min",
             LOKI, 'sum by (box) (count_over_time({box="control", source="journal", unit="k3s.service"} |~ "(?i)(back-off restarting|liveness probe failed|readiness probe failed).*(core|router|cloudflared)" [10m]))', 3, for_="0s", kind="loki"),
        rule("j2-core-change", "A new core on the control box",
             "The router saw a new core (a restart, a release or a reboot): if it is empty, Deyao Recovers it in the app",
             LOKI, 'sum(count_over_time({box="control", container="router"} |= "a new core (" [10m]))', 0, for_="0s", kind="loki", severity="critical"),
        rule("j2-probe", "jarvis2.deyaochen.com /healthz failing",
             "The external probe (Synthetic Monitoring) gets no 200 from /healthz: the router, the tunnel or the core isn't serving",
             PROM, 'min(probe_success{job="jarvis2-healthz"})', -1, for_="3m", severity="critical"),
    ]
    # the probe rule fires below 1: express it as 1 - success > 0
    r[-1]["data"][0]["model"]["expr"] = '1 - min(probe_success{job="jarvis2-healthz"})'
    r[-1]["data"][2]["model"]["conditions"][0]["evaluator"]["params"] = [0]
    r[-1]["noDataState"] = "OK"
    for b in boxes:
        x = rule(f"j2-silent-{b}", f"The {b} box has gone quiet",
                 f"No metrics from the {b} box for 5 min: the box, its Alloy or WARP is down",
                 PROM, f'absent_over_time(node_time_seconds{{box="{b}"}}[5m])', 0, for_="0s", severity="critical")
        x["noDataState"] = "OK"
        r.append(x)
    return r


def apply(boxes):
    hook = os.environ["GRAFANA_DISCORD_WEBHOOK"]
    st, cps = call("GET", "/api/v1/provisioning/contact-points?name=jarvis2-discord")
    cp = {"name": "jarvis2-discord", "type": "discord", "settings": {"url": hook, "use_discord_username": False},
          "disableResolveMessage": False}
    if isinstance(cps, list) and cps:
        cp["uid"] = cps[0]["uid"]
        print("contact point", call("PUT", f"/api/v1/provisioning/contact-points/{cp['uid']}", cp)[0])
    else:
        print("contact point", call("POST", "/api/v1/provisioning/contact-points", cp)[0])
    print("policy", call("PUT", "/api/v1/provisioning/policies",
                         {"receiver": "jarvis2-discord", "group_by": ["alertname", "box"],
                          "group_wait": "30s", "group_interval": "5m", "repeat_interval": "4h"})[0])
    st, _ = call("GET", f"/api/folders/{FOLDER}")
    if st != 200:
        print("folder", call("POST", "/api/folders", {"uid": FOLDER, "title": "Jarvis 2"})[0])
    st, body = call("PUT", f"/api/v1/provisioning/folder/{FOLDER}/rule-groups/boxes",
                    {"title": "boxes", "interval": 60, "rules": rules(boxes)})
    print("rule group boxes", st, "" if st < 300 else body)
    if st >= 300:
        sys.exit(1)


def sm(method, path, body=None):
    req = urllib.request.Request(SM + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + os.environ["GRAFANA_SM_TOKEN"],
                                          "Content-Type": "application/json", "User-Agent": "jarvis2-infra"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]


def probe():
    check = {"job": "jarvis2-healthz", "target": "https://jarvis2.deyaochen.com/healthz", "frequency": 60000,
             "timeout": 10000, "enabled": True, "probes": [1, 14], "alertSensitivity": "none", "basicMetricsOnly": True,
             "labels": [{"name": "system", "value": "jarvis2"}],
             "settings": {"http": {"method": "GET", "ipVersion": "Any", "noFollowRedirects": True, "failIfNotSSL": True,
                                   "validStatusCodes": [200],
                                   "headers": ["CF-Access-Client-Id: " + os.environ["HEALTH_PROBE_ID"],
                                               "CF-Access-Client-Secret: " + os.environ["HEALTH_PROBE_SECRET"]]}}}
    st, checks = sm("GET", "/check/list")
    old = next((c for c in checks if c.get("job") == check["job"]), None) if isinstance(checks, list) else None
    if old:
        check |= {"id": old["id"], "tenantId": old["tenantId"]}
        st, _ = sm("POST", "/check/update", check)
    else:
        st, _ = sm("POST", "/check/add", check)
    print("check jarvis2-healthz", st)


def show():
    st, g = call("GET", f"/api/v1/provisioning/folder/{FOLDER}/rule-groups/boxes")
    for r in (g.get("rules", []) if isinstance(g, dict) else []):
        print(r["uid"], "|", r["title"])
    st, cps = call("GET", "/api/v1/provisioning/contact-points")
    print("contact points:", [c["name"] for c in cps] if isinstance(cps, list) else cps)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["apply"]:
        boxes = ["control", "services"]
        if "--boxes" in a:
            boxes = [b for b in a[a.index("--boxes") + 1].split(",") if b]
        apply(boxes)
    elif a[:1] == ["probe"]:
        probe()
    elif a[:1] == ["show"]:
        show()
    else:
        sys.exit(__doc__)
