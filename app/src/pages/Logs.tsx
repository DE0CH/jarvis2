// A session's logs, read only, beside the terminal (the iPhone app's Sessions/LogViews.swift):
//  - the supervisor's log (GET api/sessions/:id/supervisor-log?after=SEQ): what the machine's supervisor wrote (boot,
//    the commands it ran, the prompts it delivered, the snapshot; never a secret), appended while open;
//  - the lifecycle log (GET api/sessions/:id/lifecycle, …/lifecycle/:op): each boot, pause, resume, upgrade and
//    destroy, with what Fly did, what the router did and the supervisor's lines, in order.
// Both are kept for the session's life, so they open for running, paused and failed sessions; while open they poll
// every 2 s (an operation only while it runs). Long lines wrap: no sideways scrolling on a phone.
import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { api } from "../lib/api";
import { Badge, Button, Card, Flex, P, Pill, Row, Rows, Spinner, Text, mono } from "../ui/kit";
import { Page, openPage } from "../ui/page";
import type { ColorName } from "../theme";

export type LogSpec = { id: string; title: string };
export type OpSpec = { id: string; title: string; op: string };

export type SupervisorLine = { seq: number; at?: string; machine?: string; text: string };
export type LifecycleEntry = { at?: string; source?: string; machine?: string; text: string };
export type LifecycleOp = { id: string; kind: string; started?: string; ended?: string; state?: string; error?: string; machines?: string[]; running?: boolean; entries?: LifecycleEntry[] };

const POLL = 2000, KEEP = 5000;

/** "12:04:31" today, "Oct 15, 12:04:31" another day (local time) */
export function clock(at?: string): string {
  if (!at) return "";
  const d = new Date(at);
  if (isNaN(+d)) return "";
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return d.toDateString() === new Date().toDateString() ? t : d.toLocaleDateString([], { month: "short", day: "numeric" }) + ", " + t;
}
/** "4 s", "2 min 5 s", "1 h 3 min" between two times (to now while it runs) */
export function duration(from?: string, to?: string): string {
  if (!from) return "";
  const s = Math.max(0, Math.floor(((to ? +new Date(to) : Date.now()) - +new Date(from)) / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return s % 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s / 60} min`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}
/** running | done | failed */
export function opState(op: LifecycleOp): string { return op.running ? "running" : op.state || (op.ended ? "done" : "running"); }
/** new lines after the ones held (by seq), the oldest dropped past KEEP */
export function mergeLines(held: SupervisorLine[], got: SupervisorLine[]): SupervisorLine[] {
  const last = held.length ? held[held.length - 1].seq : -Infinity;
  const out = held.concat(got.filter((l) => l.seq > last));
  return out.length > KEEP ? out.slice(out.length - KEEP) : out;
}

function StateBadge({ op }: { op: LifecycleOp }) {
  const s = opState(op);
  return s === "running" ? <Pill kind="wait" spin>running</Pill> : s === "failed" ? <Pill kind="bad">failed</Pill> : <Pill kind="ok">done</Pill>;
}
const SOURCES: Record<string, [string, ColorName]> = { fly: ["Fly", "amber"], router: ["Router", "blue"], supervisor: ["Supervisor", "green"] };
function SourceTag({ source }: { source?: string }) {
  const s = SOURCES[source || ""];
  return <Badge color={s ? s[1] : "gray"}>{s ? s[0] : source || "—"}</Badge>;
}
const lineStyle = { fontFamily: mono, fontSize: 12, lineHeight: 17 } as const;

export function SupervisorLogPage({ spec }: { spec: LogSpec }) {
  const [lines, setLines] = useState<SupervisorLine[]>([]), [loaded, setLoaded] = useState(false), [err, setErr] = useState("");
  const next = useRef(0), scroll = useRef<any>(null);
  useEffect(() => {
    let alive = true, t: any = null;
    const tick = async () => {
      try {
        const j = await api<{ lines: SupervisorLine[]; next?: number }>("GET", `api/sessions/${encodeURIComponent(spec.id)}/supervisor-log?after=${next.current}&limit=500`);
        if (!alive) return;
        const got = j.lines || [];
        if (got.length) setLines((h) => mergeLines(h, got));
        if (typeof j.next === "number") next.current = j.next; else if (got.length) next.current = got[got.length - 1].seq;
        setErr(""); setLoaded(true);
      } catch (e: any) { if (alive) { setErr(e.message); setLoaded(true); } }
    };
    const loop = async () => { await tick(); if (alive) t = setTimeout(loop, POLL); };
    loop();
    return () => { alive = false; clearTimeout(t); };
  }, [spec.id]);
  return (
    <Page title="Supervisor log" scrollRef={scroll} onContentSizeChange={() => scroll.current?.scrollToEnd?.({ animated: false })} id="supervisor-log">
      <Rows mt={2}><Row label="Session">{spec.title}</Row><Row label="Shows">The machine's supervisor, as it writes</Row></Rows>
      {!!err && <P size={2} color="red" mt={3} id="suplog-error">{err}</P>}
      {!loaded ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Reading the supervisor's log…</P></Flex>
        : !lines.length ? <P size={3} color="gray" align="center" mt={6} id="suplog-empty">The supervisor hasn't written anything yet.</P>
        : <View nativeID="suplog-lines" style={{ marginTop: 12, gap: 1 }}>
            {lines.map((l, i) => (
              <View key={l.seq} {...({ dataSet: { seq: String(l.seq) } } as any)}>
                {!!l.machine && (i === 0 || lines[i - 1].machine !== l.machine) && <P size={1} weight="bold" color="gray" mt={i ? 3 : 0} mb={1} selectable>machine {l.machine}</P>}
                <Text selectable style={{ ...lineStyle }}><Text color="gray" style={lineStyle}>{clock(l.at) + "  "}</Text>{l.text}</Text>
              </View>
            ))}
          </View>}
    </Page>
  );
}

export function LifecyclePage({ spec }: { spec: LogSpec }) {
  const [ops, setOps] = useState<LifecycleOp[] | null>(null), [err, setErr] = useState("");
  useEffect(() => {
    let alive = true, t: any = null;
    const loop = async () => {
      let running = false;
      try {
        const j = await api<{ ops: LifecycleOp[] }>("GET", `api/sessions/${encodeURIComponent(spec.id)}/lifecycle`);
        if (!alive) return;
        setOps(j.ops || []); setErr("");
        running = (j.ops || []).some((o) => opState(o) === "running");
      } catch (e: any) { if (alive) setErr(e.message); }
      if (alive) t = setTimeout(loop, running ? POLL : 10000);
    };
    loop();
    return () => { alive = false; clearTimeout(t); };
  }, [spec.id]);
  return (
    <Page title="Lifecycle" id="lifecycle">
      <Rows mt={2}><Row label="Session">{spec.title}</Row><Row label="Shows">Each boot, pause, resume, upgrade and destroy</Row></Rows>
      {!!err && <P size={2} color="red" mt={3} id="lifecycle-error">{err}</P>}
      {!ops ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Reading the lifecycle log…</P></Flex>
        : !ops.length ? <P size={3} color="gray" align="center" mt={6} id="lifecycle-empty">No operations recorded yet.</P>
        : <View style={{ gap: 8, marginTop: 12 }}>
            {ops.map((op) => (
              <Card key={op.id} size={1} id={"lc-op-" + op.id}>
                <Flex align="center" gap={2}>
                  <P size={3} weight="bold" style={{ flex: 1, textTransform: "capitalize" }}>{op.kind}</P>
                  <StateBadge op={op} />
                </Flex>
                <P size={1} color="gray" mt={1}>{[op.started ? clock(op.started) : "", duration(op.started, op.ended)].filter(Boolean).join(" · ")}</P>
                {!!op.error && <P size={1} color="red" mt={1} lines={2}>{op.error}</P>}
                <Flex mt={2}><Button size={1} variant="soft" id={"lc-open-" + op.id} onPress={() => openPage("lifecycle-op", { id: spec.id, title: spec.title, op: op.id })}>Show log</Button></Flex>
              </Card>
            ))}
          </View>}
    </Page>
  );
}

export function LifecycleOpPage({ spec }: { spec: OpSpec }) {
  const [op, setOp] = useState<LifecycleOp | null>(null), [err, setErr] = useState("");
  const scroll = useRef<any>(null), follow = useRef(true);
  useEffect(() => {
    let alive = true, t: any = null;
    const loop = async () => {
      let again = true;
      try {
        const j = await api<LifecycleOp>("GET", `api/sessions/${encodeURIComponent(spec.id)}/lifecycle/${encodeURIComponent(spec.op)}`);
        if (!alive) return;
        setOp(j); setErr("");
        again = opState(j) === "running";
        follow.current = again;
      } catch (e: any) { if (alive) setErr(e.message); }
      if (alive && again) t = setTimeout(loop, POLL);
    };
    loop();
    return () => { alive = false; clearTimeout(t); };
  }, [spec.id, spec.op]);
  const entries = op?.entries || [];
  return (
    <Page title={op ? op.kind.charAt(0).toUpperCase() + op.kind.slice(1) : "Operation"} id="lifecycle-op" scrollRef={scroll}
      onContentSizeChange={() => { if (follow.current) scroll.current?.scrollToEnd?.({ animated: false }); }}>
      {!!err && <P size={2} color="red" mt={3} id="lc-error">{err}</P>}
      {!op ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Reading the operation…</P></Flex>
        : <>
            <Rows mt={2}>
              <Row label="Session">{spec.title}</Row>
              <Row label="State"><StateBadge op={op} /></Row>
              {!!op.started && <Row label="Started">{clock(op.started)}</Row>}
              <Row label={opState(op) === "running" ? "Running for" : "Took"}>{duration(op.started, op.ended)}</Row>
              {!!op.machines?.length && <Row label="Machines" mono>{op.machines.join(", ")}</Row>}
              {!!op.error && <Row label="Error" color="red">{op.error}</Row>}
            </Rows>
            {!entries.length ? <P size={3} color="gray" align="center" mt={6}>{opState(op) === "running" ? "Waiting for the first step…" : "Nothing was recorded."}</P>
              : <View nativeID="lc-entries" style={{ gap: 8, marginTop: 16 }}>
                  {entries.map((e, i) => (
                    <View key={i} nativeID={"lc-entry-" + i} {...({ dataSet: { source: e.source || "" } } as any)}>
                      <Flex align="center" gap={2} wrap>
                        <Text color="gray" style={lineStyle}>{clock(e.at)}</Text>
                        <SourceTag source={e.source} />
                        {!!e.machine && <Text color="gray" style={{ ...lineStyle, fontSize: 11 }}>{e.machine}</Text>}
                      </Flex>
                      <Text selectable style={lineStyle}>{e.text}</Text>
                    </View>
                  ))}
                </View>}
          </>}
    </Page>
  );
}
