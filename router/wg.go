package main

// The machines' listener on Fly's private network: the box is a WireGuard peer of the Fly org (a peer made
// with `fly wireguard create`), and the router runs that peer itself in userspace (wireguard-go + netstack),
// so the pod needs no privileges and /m is reachable from the org's machines and nowhere else.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wgConf: the parts of a wg-quick file that `fly wireguard create` writes
type wgConf struct {
	Address, PrivateKey, PublicKey, Endpoint, AllowedIPs, Keepalive string
}

func parseWG(path string) (wgConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return wgConf{}, err
	}
	defer f.Close()
	var c wgConf
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Address":
			c.Address = v
		case "PrivateKey":
			c.PrivateKey = v
		case "PublicKey":
			c.PublicKey = v
		case "Endpoint":
			c.Endpoint = v
		case "AllowedIPs":
			c.AllowedIPs = v
		case "PersistentKeepalive":
			c.Keepalive = v
		}
	}
	if c.Address == "" || c.PrivateKey == "" || c.PublicKey == "" || c.Endpoint == "" {
		return c, fmt.Errorf("%s: missing Address/PrivateKey/PublicKey/Endpoint", path)
	}
	return c, sc.Err()
}

func b64hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("bad WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

// serveWG brings the box's WireGuard peer up and serves h on it; stop takes the peer down (the leader's handover,
// leader.go) and ends the serve. err reports a failure to come up.
func serveWG(path string, port int, h http.Handler) (stop func(), err error) {
	c, err := parseWG(path)
	if err != nil {
		return nil, err
	}
	pfx, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return nil, fmt.Errorf("Address: %w", err)
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{pfx.Addr()}, nil, 1420)
	if err != nil {
		return nil, err
	}
	ep, err := net.ResolveUDPAddr("udp", c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint %s: %w", c.Endpoint, err)
	}
	priv, err := b64hex(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := b64hex(c.PublicKey)
	if err != nil {
		return nil, err
	}
	ipc := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\n", priv, pub, ep.String())
	for _, a := range strings.Split(c.AllowedIPs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			ipc += "allowed_ip=" + a + "\n"
		}
	}
	if c.Keepalive != "" {
		ipc += "persistent_keepalive_interval=" + c.Keepalive + "\n"
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
	if err := dev.IpcSet(ipc); err != nil {
		return nil, err
	}
	if err := dev.Up(); err != nil {
		return nil, err
	}
	l, err := tnet.ListenTCP(&net.TCPAddr{IP: pfx.Addr().AsSlice(), Port: port})
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: h}
	go func() {
		if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Printf("wg: serve: %v", err)
		}
	}()
	// stop: graceful (movegate.go): idle connections get a FIN that still reaches the machines before the device goes, so
	// their next call dials anew (and waits in SYN retries for the next peer) instead of failing on a dead connection
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		srv.Shutdown(ctx)
		cancel()
		srv.Close()
		time.Sleep(300 * time.Millisecond)
		dev.Close()
	}, nil
}
