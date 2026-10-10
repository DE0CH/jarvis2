// Settings: the Claude account (Jarvis 1 holds it), the Fly spend against the cap, the core as the router
// reports it, and the shell's recovery, recovery-kit and master-key pages (the app only).
import { Linking } from "react-native";
import { useEffect, useRef, useState } from "react";
import { api, fromNow, usd, type Usage, type UsageLimit } from "../lib/api";
import { useStore, failed, pend } from "../lib/store";
import { CopyButton, PButton } from "../ui/bits";
import { hasShell, requestSecure } from "../lib/shell";
import { Box, Button, Card, Flex, Heading, Muted, P, Progress, Text } from "../ui/kit";
import { Cards } from "../ui/cards";

const short = (k?: string) => (k ? k.slice(0, 16) + "…" + k.slice(-8) : "—");
const open = (u: string) => Linking.openURL(u).catch((e) => failed(e, "Could not open the link: "));

// "Session (5 h)" / "Weekly · all models" / "Weekly · Fable" — the windows the CLI's /usage lists
function limitLabel(l: UsageLimit) {
  const scope = l.model || l.surface;
  if (l.group === "session") return "Session (5 h)";
  if (l.group === "weekly") return scope ? "Weekly · " + scope : "Weekly · all models";
  return (scope ? scope + " · " : "") + l.kind.replace(/_/g, " ");
}
function money(v: number, currency: string, dp: number) {
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: dp }).format(v / Math.pow(10, dp)); }
  catch { return (v / Math.pow(10, dp)).toFixed(dp) + " " + currency; }
}
// the Claude quota (GET api/usage, forwarded to Jarvis 1, which holds the login)
function UsageCard() {
  const [u, setU] = useState<Usage | null>(null), [err, setErr] = useState<string | null>(null);
  const seq = useRef(0); // latest request wins
  async function load(force: boolean) {
    const n = ++seq.current;
    if (force) pend("usage", "Refreshing…");
    try { const r = await api<Usage>("GET", "api/usage" + (force ? "?refresh=1" : "")); if (n === seq.current) { setU(r); setErr(null); } }
    catch (e: any) { if (n === seq.current) setErr(e.message); }
    if (force) pend("usage", null);
  }
  useEffect(() => { load(false); }, []);
  return (
    <Card data={{ settings: "usage" }}><Heading size={3} mb={1}>Usage</Heading>
      {!u && !err ? <Muted>Loading…</Muted>
        : !u ? <P size={2} color="red">{err}</P>
        : <>
          {u.limits.length === 0 && <Muted>No rate-limit windows reported.</Muted>}
          {u.limits.map((l) => {
            const used = Math.max(0, Math.min(100, l.percent));
            const color = used >= 90 ? "red" : used >= 75 ? "amber" : "green";
            return (
              <Box key={l.kind + (l.model || "") + (l.surface || "")} mt={3}>
                <Flex justify="space-between" align="baseline" gap={2}>
                  <P size={2} weight="medium" style={{ flex: 1 }}>{limitLabel(l)}</P>
                  <P size={2} color={color} weight="bold">{used}% used</P>
                </Flex>
                <Progress value={used} color={color} mt={1} />
                <Muted mt={1}>{100 - used}% left{l.resetsAt ? " · resets " + fromNow(l.resetsAt) : ""}</Muted>
              </Box>
            );
          })}
          {u.extraUsage && <Muted mt={3}>Extra usage: {u.extraUsage.enabled
            ? `${money(u.extraUsage.usedCredits, u.extraUsage.currency, u.extraUsage.decimalPlaces)} of ${money(u.extraUsage.monthlyLimit, u.extraUsage.currency, u.extraUsage.decimalPlaces)} this month${u.extraUsage.spendLimitReached ? " · spend limit reached" : ""}`
            : `off${u.extraUsage.disabledReason ? " (" + u.extraUsage.disabledReason.replace(/_/g, " ") + ")" : ""}`}</Muted>}
          <Muted mt={2}>Fetched {fromNow(u.fetchedAt)}{u.stale ? <> · <Text color="red">showing the last good reading — refresh failed: {u.error}</Text></> : ""}{err && !u.stale ? <> · <Text color="red">{err}</Text></> : ""}</Muted>
        </>}
      <Flex mt={3}><PButton pkey="usage" variant="soft" color="gray" onPress={() => load(true)} label="Refresh" id="usage-refresh" /></Flex>
    </Card>
  );
}

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
        <Muted>Jarvis 2 sessions use Jarvis 1's Claude login: the router fetches its credential pair and writes it into a session whose login expired. Re-login and the token live in Jarvis 1's Settings; the quota below is read through it.</Muted>
        <Flex mt={3}><Button variant="soft" id="open-jarvis1" onPress={() => open("https://jarvis.deyaochen.com/")}>Jarvis 1 ↗</Button></Flex>
      </Card>
      <UsageCard />
      <FlyCard />
      <Card data={{ settings: "core" }}>
        <Heading size={3} mb={1}>Core</Heading>
        <Muted>{core.up ? "Answering." : "Not answering."}</Muted>
        <Flex mt={2} gap={2} align="center"><P size={2} style={{ flex: 1 }}>Signing key</P>{!!core.signingKey && <CopyButton id="copy-core-signing" value={core.signingKey} what="Signing key" />}</Flex>
        <P size={1} mono color="gray" selectable>{short(core.signingKey)}</P>
        <Flex mt={1} gap={2} align="center"><P size={2} style={{ flex: 1 }}>Agreement key</P>{!!core.agreementKey && <CopyButton id="copy-core-agreement" value={core.agreementKey} what="Agreement key" />}</Flex>
        <P size={1} mono color="gray" selectable>{short(core.agreementKey)}</P>
        <Muted mt={2}>As the router reports them. The app trusts only the core it recovered (its 8 words checked against the box key in git).</Muted>
      </Card>
      {hasShell && <Card data={{ settings: "recovery" }}>
        <Heading size={3} mb={1}>Recovery</Heading>
        <Muted>A new or restarted core gets every store back from the backups: its 8 words, then the recovery kit from your password manager.</Muted>
        <Flex mt={3}><Button id="open-recovery" variant="soft" onPress={() => requestSecure("recovery", {})}>Open recovery</Button></Flex>
      </Card>}
      {hasShell && <Card data={{ settings: "recovery-kit" }}>
        <Heading size={3} mb={1}>Recovery kit</Heading>
        <Muted>The one string your password manager keeps: the master private key (held on the iPhone that made it, until the kit is saved) plus the backup bucket's read keys, which the setup session sealed to the master key.</Muted>
        <Flex mt={3}><Button id="open-recovery-kit" variant="soft" color="gray" onPress={() => requestSecure("recovery-kit", {})}>Make the recovery kit…</Button></Flex>
      </Card>}
      {hasShell && <Card data={{ settings: "master-key" }}>
        <Heading size={3} mb={1}>Master key</Heading>
        <Muted>A new setup starts here: this iPhone makes the pair and shows only the public half, for you to send to Claude (it goes into the repo). The private half stays on this iPhone until it goes into your recovery kit.</Muted>
        <Flex mt={3}><Button id="open-master-key" variant="soft" color="gray" onPress={() => requestSecure("master-key", {})}>Make a master key pair…</Button></Flex>
      </Card>}
    </Cards>
  );
}
