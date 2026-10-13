# warp-host.sh — the box's network for an IPv6-only server (Deyao, 2026-10-13: every Hetzner server is IPv6-only, the
# account being at its limit of 10 primary IPs). Defines warp_host_setup; create.sh puts this file into the user-data
# ahead of cloud-init.sh, and infra/convert-ipv6.sh installs it on an existing box (run at boot before k3s).
#
# - Cloudflare's free WARP client carries the outgoing IPv4: github.com, api.github.com, ghcr.io and Fly's WireGuard
#   gateways have no IPv6. mode tunnel_only = no WARP DNS proxy (systemd-resolved keeps Hetzner's IPv6 resolvers);
#   `tunnel ip add-range ::/0` = IPv6 stays native, outside the tunnel. Cloudflare's package repo answers over IPv6.
#   (The same steps for every other Hetzner box Claude makes: claude-env scripts/hetzner-warp.sh.)
# - k3s stays an IPv4 cluster: on an IPv6-only host it would pick the IPv6 address and build an IPv6-only cluster whose
#   pods reach no IPv4 at all. So the node gets a fixed private IPv4 on a dummy interface (10.0.0.0/8 is outside the
#   WARP tunnel), pods' IPv4 goes out masqueraded through WARP, and CoreDNS forwards to IPv4 resolvers (through WARP;
#   the host's resolvers are IPv6, which the pods don't have). Set in /etc/rancher/k3s/config.yaml, read by every k3s
#   start, so the same file serves a new box and a converted one.
# Idempotent. Returns 0 once IPv4 works (curl -4 api.github.com), 1 after 2 min without.
K3S_NODE_IP=10.254.254.1
warp_host_setup() {
  export DEBIAN_FRONTEND=noninteractive
  if ! command -v warp-cli >/dev/null; then
    . /etc/os-release
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg || return 1
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $VERSION_CODENAME main" \
      > /etc/apt/sources.list.d/cloudflare-client.list
    apt-get update -y && apt-get install -y cloudflare-warp || return 1
  fi
  systemctl enable --now warp-svc
  for i in $(seq 1 30); do warp-cli --accept-tos status >/dev/null 2>&1 && break; sleep 2; done
  warp-cli --accept-tos registration show >/dev/null 2>&1 || warp-cli --accept-tos registration new || return 1
  warp-cli --accept-tos mode tunnel_only
  warp-cli --accept-tos tunnel ip list 2>/dev/null | grep -q '^ *::/0' || warp-cli --accept-tos tunnel ip add-range ::/0
  warp-cli --accept-tos connect

  cat > /etc/systemd/network/10-k3s0.netdev <<'UNIT'
[NetDev]
Name=k3s0
Kind=dummy
UNIT
  cat > /etc/systemd/network/10-k3s0.network <<UNIT
[Match]
Name=k3s0
[Network]
Address=$K3S_NODE_IP/32
UNIT
  networkctl reload
  for i in $(seq 1 15); do ip -4 addr show k3s0 2>/dev/null | grep -q "$K3S_NODE_IP" && break; sleep 1; done
  mkdir -p /etc/rancher/k3s
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/rancher/k3s/resolv.conf
  printf 'node-ip: %s\nflannel-iface: k3s0\nresolv-conf: /etc/rancher/k3s/resolv.conf\n' "$K3S_NODE_IP" > /etc/rancher/k3s/config.yaml

  for i in $(seq 1 60); do curl -4 -fsS -m 5 https://api.github.com -o /dev/null && { echo "WARP: IPv4 works"; return 0; }; sleep 2; done
  echo "WARP: no IPv4 after 2 min"; warp-cli --accept-tos status; return 1
}
