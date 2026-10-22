# PLAN: one cluster, the kernel on it (Deyao, 2026-10-22)

Deyao guides every step: each step is shown in chat, then a go/no-go, then done. No decision is taken without him.

## Decided
- One Kubernetes cluster that can span several nodes, on a NEW clean Hetzner VM; the old VMs (jarvis2-control,
  jarvis2-services) never join it: they are drained and deleted at the end. The control plane's share is held by
  Kubernetes memory reservations, not by separate clusters (replaces DECISIONS 186's two clusters).
- The kernel has no box key. Each component generates its own key inside its container. The root key (Deyao's phone)
  vouches for them: a setup session reads each component's public key straight from the new cluster's API, signs the
  list with the setup key (keys/setup.pub), and the app checks it and signs it with the root key under one Face ID.
  The old core keeps the box key until it is gone.
- Blue/green = two fully independent kernel copies. Each knows only its own components and rejects everything else;
  the router tracks which copy each line is on and writes store changes to both; the phone has keys per copy.

## Steps
0. This plan.
1. The new cluster on a new Hetzner VM (size, price, availability, IP to be settled with Deyao first).
2. The kernel on it, components generating their own keys; the one-time setup (B) with the root key.
3. Two independent kernel copies.
4. An ad hoc router that works with all three clusters (old control, old services, new).
5. Move everything over to the new cluster.
6. The router in its proper form.
7. Drain the old clusters; delete their VMs.

- Everything about the kernel's identity lives in RAM only (Deyao, 2026-10-22): a component makes a new key at every
  start, so after a restart or release it works again only once the one-time setup has run for it (Face ID).
- Git manages the whole cluster (Deyao, 2026-10-22): Flux applies k8s/cluster as cluster admin, its own sync included;
  only the k3s install and the age key come from cloud-init.
- Setup sessions reach only the kernel's read-only identity endpoints, at kernel-id.deyaochen.com behind Cloudflare
  Access (service token jarvis2-kernel-id, infra store KERNEL_ID_ACCESS_ID/SECRET); no Kubernetes login.

## Done
- Step 1 (2026-10-22): jarvis2-cluster-1 (cx23, fsn1, 10.77.0.4), k3s --cluster-init, Flux on k8s/cluster; logs in
  Grafana as box="cluster".
- Step 2a (2026-10-22): the tunnel jarvis2-cluster, its cloudflared in jarvis2-edge; kernel-id.deyaochen.com answers 200
  with the service token and 403 without (a test page until the kernel's identity endpoints replace it).
