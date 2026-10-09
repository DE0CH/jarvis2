// Settings: the Claude account (Jarvis 1 holds it), the Fly spend against the cap, the core as the router
// reports it, and the shell's recovery and master-key pages (the app only).
import { Linking } from "react-native";
import { usd } from "../lib/api";
import { useStore, failed } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Button, Card, Flex, Heading, Muted, P, Progress } from "../ui/kit";
import { Cards } from "../ui/cards";

const short = (k?: string) => (k ? k.slice(0, 16) + "…" + k.slice(-8) : "—");
const open = (u: string) => Linking.openURL(u).catch((e) => failed(e, "Could not open the link: "));

function FlyCard() {
  const b = useStore((s) => s.state.budget), fly = useStore((s) => s.state.fly), app = useStore((s) => s.state.flyApp);
  const pct = b && b.capUsd ? Math.min(100, Math.round((b.spentUsd / b.capUsd) * 100)) : 0;
  return (
    <Card data={{ settings: "fly" }}>
      <Heading size={3} mb={1}>Fly spend</Heading>
      {!b ? <Muted>{fly?.error ? "No reading: " + fly.error : "No reading yet (the router samples the Fly app every few minutes)."}</Muted>
        : <>
          <Flex justify="space-between" align="baseline" gap={2} mt={1}>
            <P size={2} weight="medium" style={{ flex: 1 }} id="budget-spent">{`${usd(b.spentUsd)} of ${usd(b.capUsd)} · ${b.month}`}</P>
            <P size={2} weight="bold" color={b.capped ? "red" : b.warned ? "amber" : "green"}>{pct}%</P>
          </Flex>
          <Progress value={pct} color={b.capped ? "red" : b.warned ? "amber" : "green"} mt={1} />
          <Muted mt={2}>{`Now ${usd(b.ratePerHour)}/h (${usd(b.perMonth)} a month at this rate) · ${b.running} running machine${b.running === 1 ? "" : "s"} · ${b.volumes} volume${b.volumes === 1 ? "" : "s"}`}</Muted>
          <Muted mt={1}>{`A DM at ${usd(b.warnUsd)}; at ${usd(b.capUsd)} the router pauses every running session.${b.capped && b.cappedAt ? " Capped " + new Date(b.cappedAt).toLocaleString() + "." : ""}${b.sampledAt ? " Sampled " + new Date(b.sampledAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + "." : ""}`}</Muted>
        </>}
      <Muted mt={2}>{`Fly app ${app || "jarvis2-sessions"} (org jarvis2-370). An estimate from the machines' sizes and running time, not Fly's invoice.`}</Muted>
    </Card>
  );
}

export function Settings() {
  const core = useStore((s) => s.state.core);
  return (
    <Cards>
      <Card data={{ settings: "claude" }}>
        <Heading size={3} mb={1}>Claude account</Heading>
        <Muted>Jarvis 2 sessions use Jarvis 1's Claude login: the router fetches its credential pair and writes it into a session whose login expired. Re-login, usage and the token live in Jarvis 1's Settings.</Muted>
        <Flex mt={3}><Button variant="soft" id="open-jarvis1" onPress={() => open("https://jarvis.deyaochen.com/")}>Jarvis 1 ↗</Button></Flex>
      </Card>
      <FlyCard />
      <Card data={{ settings: "core" }}>
        <Heading size={3} mb={1}>Core</Heading>
        <Muted>{core.up ? "Answering." : "Not answering."}</Muted>
        <P size={2} mt={2}>Signing key</P>
        <P size={1} mono color="gray" selectable>{short(core.signingKey)}</P>
        <P size={2} mt={1}>Agreement key</P>
        <P size={1} mono color="gray" selectable>{short(core.agreementKey)}</P>
        <Muted mt={2}>As the router reports them. The app trusts only the core it recovered (its 8 words checked against the box key in git).</Muted>
      </Card>
      {hasShell && <Card data={{ settings: "recovery" }}>
        <Heading size={3} mb={1}>Recovery</Heading>
        <Muted>A new or restarted core gets every store back from the backups: its 8 words, then the master key and the bucket's read keys from your password manager.</Muted>
        <Flex mt={3}><Button id="open-recovery" variant="soft" onPress={() => requestSecure("recovery", {})}>Open recovery</Button></Flex>
      </Card>}
      {hasShell && <Card data={{ settings: "master-key" }}>
        <Heading size={3} mb={1}>Master key</Heading>
        <Muted>First setup only: make the master key pair on this iPhone. The private half goes to your password manager, the public half into the repo.</Muted>
        <Flex mt={3}><Button id="open-master-key" variant="soft" color="gray" onPress={() => requestSecure("master-key", {})}>Make a master key pair…</Button></Flex>
      </Card>}
    </Cards>
  );
}
