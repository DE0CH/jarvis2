// Remote control of a session the Claude app does not see (GET api/sessions/:id/remote, Jarvis 1's Remote page):
//   OpenCode  its Paseo daemon publishes a web UI through the session's tunnel origin behind Cloudflare Access,
//             and the Paseo app pairs with the link below (over Paseo's end-to-end-encrypted relay).
//   OpenClaw  the gateway's Control UI on the same tunnel origin (the link carries the gateway token); the
//             OpenClaw app finds the session by itself through the router (GET /api/remotes).
// The router reads these inside the machine as the `remote` feature, so the phone may have to allow it first.
import { useEffect, useState } from "react";
import { Linking, View } from "react-native";
import QRCode from "qrcode";
import { SvgXml } from "react-native-svg";
import { api } from "../lib/api";
import { requestGrant } from "../lib/grants";
import { hasShell } from "../lib/shell";
import { failed } from "../lib/store";
import { CopyButton } from "../ui/bits";
import { Button, Flex, Lbl, Muted, P, Spinner } from "../ui/kit";
import { Page } from "../ui/page";

export type RemoteSpec = { id: string; title: string };
type RemoteInfo = { webUrl: string; harness?: string; pairUrl?: string; relay?: boolean; url?: string; token?: string };
const open = (u: string) => Linking.openURL(u).catch((e) => failed(e, "Could not open the link: "));

export function Remote({ spec }: { spec: RemoteSpec }) {
  const [info, setInfo] = useState<RemoteInfo | null>(null), [err, setErr] = useState(""), [grant, setGrant] = useState(false), [n, setN] = useState(0);
  useEffect(() => {
    let live = true;
    setErr(""); setInfo(null);
    api<RemoteInfo>("GET", "api/sessions/" + spec.id + "/remote").then((j) => { if (live) setInfo(j); },
      (e) => { if (live) { setErr(e.message); setGrant(e.status === 403); } });
    return () => { live = false; };
  }, [spec.id, n]);
  // a real square QR (SVG, dark on white with a quiet zone) of the paseo:// link: the native Paseo app imports
  // any URL with #offer= on open (app.paseo.sh only opens Paseo's web app)
  const appUrl = info?.pairUrl && info.pairUrl.includes("#offer=") ? "paseo:///" + info.pairUrl.slice(info.pairUrl.indexOf("#offer=")) : "";
  const [qr, setQr] = useState("");
  useEffect(() => {
    if (!appUrl) return;
    let live = true;
    QRCode.toString(appUrl, { type: "svg", margin: 4, errorCorrectionLevel: "M", color: { dark: "#000000", light: "#ffffff" } }).then((svg) => { if (live) setQr(svg); }, () => {});
    return () => { live = false; };
  }, [appUrl]);
  return (
    <Page title={spec.title} id="remote-page">
      {err ? <>
          <P size={2} color="red" mt={3} id="rm-error">{err}</P>
          {grant && hasShell && <Flex mt={3}><Button id="rm-allow" onPress={() => requestGrant(spec.id, spec.title, { holder: "remote", kind: "grant", minutes: 10 }, (ok) => { if (ok) setN((x) => x + 1); })}>Allow the remote page for 10 minutes</Button></Flex>}
        </>
        : !info ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Loading…</P></Flex>
        : <>
            <Lbl>Web UI</Lbl>
            <Flex gap={2} wrap>
              <Button id="rm-web" href={info.webUrl} onPress={() => open(info.webUrl)}>{info.harness === "openclaw" ? "Open the Control UI" : "Open the web UI"}</Button>
              <CopyButton size={2} id="rm-copy-web" value={info.webUrl} what="Link" label="Copy link" />
            </Flex>
            {info.harness === "openclaw"
              ? <Muted mt={1}>The session’s OpenClaw Control UI, behind the same Cloudflare login as this page. The link carries the gateway token — don’t share it. The OpenClaw app lists this session by itself once the app is paired.</Muted>
              : <Muted mt={1}>The session’s own Paseo page, behind the same Cloudflare login as this page. One session’s web UI per browser at a time — opening another session’s moves it over.</Muted>}
            {!!info.pairUrl && <>
              <Lbl>Paseo app</Lbl>
              <Flex gap={2} wrap>
                <Button id="rm-pair" href={appUrl || info.pairUrl} self onPress={() => open(appUrl || info.pairUrl!)}>Pair this device</Button>
                <CopyButton size={2} id="rm-copy-pair" value={info.pairUrl} what="Pairing link" label="Copy pairing link" />
              </Flex>
              <P size={1} mono color="gray" selectable mt={2}>{info.pairUrl}</P>
              <Muted mt={1}>Opens the Paseo app with this session’s pairing offer (or paste the link under “Paste pairing link” in the app). The link is the key to the session — don’t share it. From another device, scan with the camera:</Muted>
              {!!qr && <View nativeID="rm-qr" style={{ marginTop: 8, width: "100%", maxWidth: 320, aspectRatio: 1, backgroundColor: "#fff", borderRadius: 8, overflow: "hidden" }}><SvgXml xml={qr} width="100%" height="100%" /></View>}
            </>}
          </>}
    </Page>
  );
}
