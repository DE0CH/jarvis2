// Settings: the Claude account (the router holds it: status, Refresh, Re-login), its usage, the repos and their deploy
// keys (Repos.tsx), the Fly spend against the cap, and whether Jarvis 2 runs, with
// the way into the shell's Reset or recover page (the app only).
import { Linking } from "react-native";
import { useEffect, useRef, useState } from "react";
import { api, fromNow, usd, type Usage, type UsageLimit } from "../lib/api";
import { useStore, failed, pend } from "../lib/store";
import { PButton } from "../ui/bits";
import { hasShell, requestSecure } from "../lib/shell";
import { Badge, Box, Button, Card, Flex, Heading, Muted, P, Pill, Progress, Row, Rows, TextField } from "../ui/kit";
import { Cards } from "../ui/cards";
import { ReposCard } from "./Repos";
import { PairedAppsCard } from "./PairedApps";

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
type ClaudeLogin = { mode: "own" | "follow"; hasLogin: boolean; expiresAt: number | null; expired: boolean; email: string; source: string;
  refreshedAt: string | null; needLogin?: boolean; error?: string; loginInProgress: boolean };

// the Claude login (GET api/claude-login; router/claudelogin.go): account, expiry, who refreshes it; Refresh (when the
// router refreshes it) and Re-login (the CLI's sign-in: open the page, sign in, paste the code it shows)
function ClaudeCard() {
  const [l, setL] = useState<ClaudeLogin | null>(null), [err, setErr] = useState<string | null>(null);
  const [signing, setSigning] = useState(false), [code, setCode] = useState("");
  async function load() {
    try { setL(await api<ClaudeLogin>("GET", "api/claude-login")); setErr(null); } catch (e: any) { setErr(e.message); }
  }
  useEffect(() => { load(); }, []);
  async function refreshToken() {
    pend("claude-refresh", "Refreshing…");
    try { await api("POST", "api/claude-login/refresh"); await load(); } catch (e) { failed(e); }
    pend("claude-refresh", null);
  }
  async function start() {
    pend("claude-start", "Opening…");
    try { const r = await api<{ url: string }>("POST", "api/claude-login/start"); setSigning(true); setCode(""); open(r.url); } catch (e) { failed(e); }
    pend("claude-start", null);
  }
  async function finish() {
    pend("claude-code", "Signing in…");
    try { await api("POST", "api/claude-login/code", { code: code.trim() }); setSigning(false); setCode(""); await load(); } catch (e) { failed(e); }
    pend("claude-code", null);
  }
  return (
    <Card data={{ settings: "claude" }}>
      <Heading size={3} mb={1}>Claude account</Heading>
      {!l && !err ? <Muted>Loading…</Muted> : !l ? <P size={2} color="red">{err}</P> : <>
        <Rows id="claude-rows">
          <Row label="Account">{l.email || "—"}</Row>
          <Row label="Login">{l.needLogin ? <Badge color="red">Re-login needed</Badge> : l.expired ? <Badge color="red">expired</Badge> : <Badge color="green">ok</Badge>}</Row>
          {!!l.expiresAt && <Row label="Token valid">{fromNow(new Date(l.expiresAt))}</Row>}
          <Row label="Refreshed by">{l.mode === "own" ? "Jarvis 2" : "Jarvis 1"}</Row>
          {!!l.refreshedAt && <Row label="Last refresh">{fromNow(l.refreshedAt)}</Row>}
          {!!l.error && <Row label="Error" color="red">{l.error}</Row>}
        </Rows>
        <Flex mt={3} gap={2} wrap>
          {l.mode === "own" && <PButton pkey="claude-refresh" id="claude-refresh" variant="soft" label="Refresh token" onPress={refreshToken} />}
          <PButton pkey="claude-start" id="claude-relogin" variant="soft" label="Re-login" onPress={start} />
        </Flex>
        {signing && <Box mt={3}>
          <Muted>Paste the code the sign-in page shows.</Muted>
          <Flex mt={2} gap={2} align="center">
            <Box style={{ flex: 1 }}><TextField id="claude-code" autoCapitalize="none" autoCorrect={false} autoComplete="off" placeholder="code#state" value={code} onChangeText={setCode} /></Box>
            <PButton pkey="claude-code" id="claude-code-submit" label="Sign in" cool={!code.includes("#")} onPress={finish} />
          </Flex>
        </Box>}
      </>}
    </Card>
  );
}

// the Claude quota (GET api/usage, from the router's Claude login)
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
                <Rows mt={1}>
                  <Row label="Left">{`${100 - used}%`}</Row>
                  {!!l.resetsAt && <Row label="Resets">{fromNow(l.resetsAt)}</Row>}
                </Rows>
              </Box>
            );
          })}
          <Rows mt={3} id="usage-rows">
            {u.extraUsage && (u.extraUsage.enabled ? <>
              <Row label="Extra usage">{u.extraUsage.spendLimitReached ? <Badge color="red">limit reached</Badge> : <Badge color="green">on</Badge>}</Row>
              <Row label="Used this month">{money(u.extraUsage.usedCredits, u.extraUsage.currency, u.extraUsage.decimalPlaces)}</Row>
              <Row label="Monthly limit">{money(u.extraUsage.monthlyLimit, u.extraUsage.currency, u.extraUsage.decimalPlaces)}</Row>
            </> : <>
              <Row label="Extra usage"><Badge>off</Badge></Row>
              {!!u.extraUsage.disabledReason && <Row label="Why off">{u.extraUsage.disabledReason.replace(/_/g, " ")}</Row>}
            </>)}
            <Row label="Fetched">{u.stale ? <><P size={2}>{fromNow(u.fetchedAt)}</P><Badge color="amber">last good reading</Badge></> : fromNow(u.fetchedAt)}</Row>
            {u.stale && !!u.error && <Row label="Refresh failed" color="red">{u.error}</Row>}
            {!!err && !u.stale && <Row label="Error" color="red">{err}</Row>}
          </Rows>
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
      {!b ? <Rows><Row label="Reading" color={fly?.error ? "red" : undefined}>{fly?.error || "None yet"}</Row></Rows>
        : <>
          <Flex justify="space-between" align="baseline" gap={2} mt={1}>
            <P size={2} weight="medium" style={{ flex: 1 }} id="budget-spent">{usd(b.spentUsd)}</P>
            <P size={2} weight="bold" color={b.capped ? "red" : b.warned ? "amber" : "green"}>{pct}%</P>
          </Flex>
          <Progress value={pct} color={b.capped ? "red" : b.warned ? "amber" : "green"} mt={1} />
          <Rows mt={2} id="budget-rows">
            <Row label="Month">{b.month}</Row>
            <Row label="Cap" id="budget-cap">{usd(b.capUsd)}</Row>
            <Row label="DM at">{usd(b.warnUsd)}</Row>
            <Row label="Rate">{usd(b.ratePerHour) + " / h"}</Row>
            <Row label="At this rate">{usd(b.perMonth) + " / month"}</Row>
            <Row label="Running">{String(b.running)}</Row>
            <Row label="Volumes">{String(b.volumes)}</Row>
            {b.capped && !!b.cappedAt && <Row label="Capped" color="red">{new Date(b.cappedAt).toLocaleString()}</Row>}
            {!!b.sampledAt && <Row label="Sampled">{new Date(b.sampledAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</Row>}
          </Rows>
        </>}
      <Rows mt={2}>
        <Row label="Fly app">{app || "jarvis2-sessions"}</Row>
        <Row label="Org">jarvis2-370</Row>
      </Rows>
      <Muted mt={2}>At the cap, every running session is paused. An estimate, not Fly's invoice.</Muted>
    </Card>
  );
}

export function Settings() {
  const st = useStore((s) => s.state);
  return (
    <Cards>
      <ClaudeCard />
      <UsageCard />
      <ReposCard />
      <FlyCard />
      <PairedAppsCard />
      <Card data={{ settings: "setup" }}>
        <Heading size={3} mb={1}>Jarvis 2</Heading>
        <Rows>
          <Row label="Secrets" id="secrets-status">{st.secrets.up ? <Pill kind="ok">running</Pill> : <Pill kind="bad">not answering</Pill>}</Row>
          <Row label="Root grant" id="root-grant-status">{st.rootGrant ? <Pill kind="ok">given</Pill> : <Pill kind="bad">missing</Pill>}</Row>
        </Rows>
        {hasShell && <>
          <Flex mt={3}><Button id="open-setup" variant="soft" onPress={() => requestSecure("setup", {})}>Reset or recover…</Button></Flex>
        </>}
      </Card>
    </Cards>
  );
}
