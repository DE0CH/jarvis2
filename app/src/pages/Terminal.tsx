// Live terminal (Jarvis 1's Terminal page): the harness's tmux pane, one snapshot at a time
// (GET api/sessions/:id/terminal — the pane the machine pushes itself, viewing needs nothing), keystrokes sent as
// tmux send-keys (POST …/terminal). The screen is drawn as React Native text from the capture's colour
// escapes (ui/ansi.ts). Typing and resizing are shell commands, which the machine runs only while a terminal
// (an add-on the iPhone approved, 10 minutes at most) is open; the page says when none is and files one.
//
// A full-screen page, always dark: close with ✕, Back, or the swipe-back. A change of the screen area
// (open, rotation, keyboard) resizes the remote tmux window to fit.
import { useEffect, useRef, useState } from "react";
import { ScrollView, View, type LayoutChangeEvent } from "react-native";
import { RNText } from "../ui/rntext";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import { api } from "../lib/api";
import { needsTerminal, requestTerminal } from "../lib/addons";
import { useStore } from "../lib/store";
import { LockedStore } from "../views/Sessions";
import { ForceScheme } from "../theme";
import { Button, Flex, Heading, P, TextField, mono } from "../ui/kit";
import { closePage } from "../ui/page";
import { colours, parseScreen, TERM_BG, type Run } from "../ui/ansi";
import { TermBody, useTermFrame } from "./termFrame";

export type TermSpec = { id: string; title: string };
// the keys the router passes to tmux (router/terminal.go tmuxKeys)
const KEYS: [string, string][] = [["Enter", "Enter"], ["Esc", "Escape"], ["Tab", "Tab"], ["⇧Tab", "BTab"], ["↑", "Up"], ["↓", "Down"], ["←", "Left"], ["→", "Right"], ["⌫", "BSpace"], ["^C", "C-c"], ["^D", "C-d"], ["^R", "C-r"], ["^U", "C-u"], ["PgUp", "PageUp"], ["PgDn", "PageDown"]];
const BAR = "#161a22";
const FONT = 12, CW = FONT * 0.602, LH = Math.round(FONT * 1.25);

function Line({ runs }: { runs: Run[] }) {
  return (
    <RNText style={{ fontFamily: mono, fontSize: FONT, lineHeight: LH, color: "#d4d4d4" }} numberOfLines={1}>
      {runs.length ? runs.map((r, i) => (
        <RNText key={i} style={{ ...colours(r.style), fontWeight: r.style.bold ? "700" : "400", fontStyle: r.style.italic ? "italic" : "normal", textDecorationLine: r.style.underline ? "underline" : "none" }}>{r.text}</RNText>
      )) : " "}
    </RNText>
  );
}

export function TerminalPage({ spec }: { spec: TermSpec }) {
  const id = spec.id;
  const session = useStore((st) => st.state.sessions.find((x) => x.id === spec.id));
  const ins = useSafeAreaInsets(), frame = useTermFrame();
  const [lines, setLines] = useState<Run[][]>([]);
  const [status, setStatus] = useState("connecting…");
  const [err, setErr] = useState<string | null>(null); // the picture failed (the next good picture clears it)
  // typing or resizing was refused: kept until input goes through, so a working view-only picture doesn't hide it
  const [inErr, setInErr] = useState<string | null>(null);
  const typing = useRef(false); // the last input went through: a terminal is open
  const [closed, setClosed] = useState(false); // the last input was refused for want of a terminal (needsTerminal)
  const [text, setText] = useState("");
  // a terminal in force on the running machine (the session's addOns)
  const open = (session?.addOns || []).some((a) => a.kind === "terminal" && Date.parse(a.until) > Date.now());

  // input strictly in order, one request at a time (each POST is its own exec); text typed while one is in
  // flight joins the next request
  const outq = useRef<{ text?: string; keys?: string[] }[]>([]), sending = useRef(false);
  async function send(body: { text?: string; keys?: string[] }) {
    const q = outq.current, lastB = q[q.length - 1];
    if (body.text && !body.keys && lastB && lastB.text && !lastB.keys) lastB.text += body.text; else q.push({ ...body });
    if (sending.current) return;
    sending.current = true;
    try {
      while (q.length) {
        const b = q.shift()!;
        try { await api("POST", `api/sessions/${id}/terminal`, b); typing.current = true; setInErr(null); setClosed(false); }
        catch (e: any) { typing.current = false; if (needsTerminal(e)) { setClosed(true); setInErr(null); } else setInErr(e.message); }
      }
    } finally { sending.current = false; }
  }
  function sendText() { const t = text; setText(""); send(t ? { text: t, keys: ["Enter"] } : { keys: ["Enter"] }); }

  // fit: the screen area in character cells → the remote tmux window (debounced; only on a change)
  const wanted = useRef(""), timer = useRef<any>(null);
  const onLayout = (e: LayoutChangeEvent) => {
    const { width, height } = e.nativeEvent.layout;
    const cols = Math.max(20, Math.min(300, Math.floor((width - 12) / CW))), rows = Math.max(5, Math.min(120, Math.floor((height - 12) / LH)));
    const k = cols + "x" + rows;
    if (k === wanted.current) return;
    wanted.current = k;
    clearTimeout(timer.current);
    // without a terminal the picture keeps the window's own size, quietly (viewing needs nothing)
    timer.current = setTimeout(() => api("POST", `api/sessions/${id}/terminal`, { cols, rows })
      .then(() => { typing.current = true; }, (e) => { wanted.current = ""; if (!needsTerminal(e)) setInErr(e.message); }), 400);
  };

  // one snapshot at a time, the next a second after the last answered (an older frame never paints over a newer one)
  const last = useRef("");
  useEffect(() => {
    let alive = true, next: any = null;
    const tick = async () => {
      try {
        // the machine pushes its own pane (`at`): viewing needs no terminal (router/terminal.go)
        const f = await api<{ screen: string; cursor: string; at?: string }>("GET", `api/sessions/${id}/terminal`);
        if (!alive) return;
        setErr(null);
        const [x, y, w, h, vis] = String(f.cursor || "").split(",").map((v) => parseInt(v, 10));
        setStatus((f.at && !typing.current ? "view only" : "live") + (w ? ` · ${w}×${h}` : ""));
        const key = f.screen + "|" + f.cursor;
        if (key === last.current) return;
        last.current = key;
        setLines(parseScreen(f.screen, vis ? [x, y] : null));
      } catch (e: any) { if (alive) { setErr(e.message); setStatus("no picture"); } }
    };
    const loop = async () => { await tick(); if (alive) next = setTimeout(loop, 1000); };
    loop();
    return () => { alive = false; clearTimeout(next); clearTimeout(timer.current); };
  }, [id]);

  return (
    <ForceScheme scheme="dark">
      <StatusBar style="light" />
      <View nativeID="terminal" accessibilityLabel="Terminal" style={[{ backgroundColor: TERM_BG }, frame.style]}>
        <Flex align="center" gap={2} style={{ paddingTop: 8 + ins.top, paddingBottom: 8, paddingHorizontal: 10, borderBottomWidth: 1, borderBottomColor: "#222", backgroundColor: BAR }}>
          <Heading size={3} lines={1} style={{ flex: 1, minWidth: 0 }}>{spec.title}</Heading>
          <P size={1} lines={1} id="term-status" style={{ fontSize: 11, color: "#9aa1ab", maxWidth: "45%" }}>{status}</P>
          <Button variant="soft" color="gray" size={1} onPress={closePage} label="Close" id="term-close">✕</Button>
        </Flex>
        {!!session?.lockedStore && <View style={{ padding: 8 }}><LockedStore m={session} compact /></View>}
        {!!err && <View nativeID="term-err" style={{ paddingHorizontal: 12, paddingVertical: 8, backgroundColor: "#2a2113" }}><P size={1} style={{ color: "#f1c27d" }}>{err}</P></View>}
        {!!inErr && <View nativeID="term-in-err" style={{ paddingHorizontal: 12, paddingVertical: 8, backgroundColor: "#2a2113" }}><P size={1} style={{ color: "#f1c27d" }}>{inErr}</P></View>}
        {(closed || !open) && session?.state === "started" && (
          <View nativeID="term-note" style={{ paddingHorizontal: 12, paddingVertical: 8, backgroundColor: "#2a2113", gap: 6 }}>
            <P size={1} style={{ color: "#f1c27d" }}>{closed ? "Typing needs a terminal." : "View only: no terminal open."}</P>
            <Flex gap={2}><Button size={1} id="term-allow" onPress={() => requestTerminal(id)}>Ask the iPhone for 10 minutes</Button></Flex>
          </View>
        )}
        <TermBody>{(kb) => <>
          <View style={{ flex: 1, overflow: "hidden", padding: 6 }} onLayout={onLayout}>
            <ScrollView horizontal bounces={false} showsHorizontalScrollIndicator={false}>
              <View nativeID="term-screen">{lines.map((runs, i) => <Line key={i} runs={runs} />)}</View>
            </ScrollView>
          </View>
          <ScrollView nativeID="term-keys" horizontal keyboardShouldPersistTaps="always" showsHorizontalScrollIndicator={false} style={{ flexGrow: 0, borderTopWidth: 1, borderTopColor: "#222", backgroundColor: BAR }} contentContainerStyle={{ gap: 6, paddingHorizontal: 8, paddingVertical: 6 }}>
            {/* key chips must not steal focus from the input (that would drop the keyboard) */}
            {KEYS.map(([l, k]) => <Button key={k} variant="soft" color="gray" size={1} keepFocus onPress={() => send({ keys: [k] })}>{l}</Button>)}
          </ScrollView>
          <Flex gap={2} style={{ paddingHorizontal: 8, paddingTop: 6, paddingBottom: kb ? 8 : 8 + ins.bottom, backgroundColor: BAR }}>
            <TextField id="term-in" style={{ flex: 1, fontFamily: mono }} autoComplete="off" autoCorrect={false} autoCapitalize="none" spellCheck={false}
              returnKeyType="send" submitBehavior="submit" placeholder="type, then Send (adds Enter)" value={text} onChangeText={setText} onSubmitEditing={sendText} />
            <Button variant="soft" color="gray" keepFocus onPress={sendText} id="term-send">Send</Button>
          </Flex>
        </>}</TermBody>
      </View>
    </ForceScheme>
  );
}
