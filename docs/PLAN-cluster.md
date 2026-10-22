# PLAN: one cluster, the kernel on it — moved to Jarvis 4 (Deyao, 2026-10-22)

The changes grew large enough that Deyao made them a new system: **Jarvis 4** (DE0CH/jarvis4, a copy of this repo with
its history), running alongside Jarvis 2. The new cluster jarvis2-cluster-1 (cx23, fsn1, 10.77.0.4) is Jarvis 4's: its
Flux reads DE0CH/jarvis4 (k8s/cluster/flux-sync.yaml here points there, then this repo's k8s/cluster goes).

Jarvis 2 stays as it is: the control and services boxes, the core, the router, the app. Its plan for the kernel
(docs/PLAN-grants.md, DESIGN "Target design") is carried on in DE0CH/jarvis4's docs/PLAN-cluster.md.
