// Everything that opens on top of the screen, on every device, with NO motion — it appears and
// disappears instantly (Deyao: a bottom sheet with its animation and gestures looked and behaved janky):
//   store.ask()  → <ConfirmHost>: a small centered dialog (Enter confirms, Esc cancels on the web)
//   action menu  → openMenu(): a dropdown anchored under (or above) its button
//   store.toast  → <Toasts>: notices at the bottom of the screen (top right with a mouse)
// The hosts render once, at the root, above every screen.
import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { Platform, Pressable, ScrollView, View, useWindowDimensions, type View as RNView } from "react-native";
import { KeyboardAvoidingView } from "react-native-keyboard-controller";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useStore, answer, dismissToast } from "../lib/store";
import { useTheme, radius } from "../theme";
import { Button, Flex, Heading, P, Text, TextArea, TextField, CalloutText, ids } from "./kit";

export const isWeb = Platform.OS === "web";
// a real mouse (decides small things: focusing a field on open, "Click" vs "Tap")
export const mouse = () => isWeb && typeof matchMedia !== "undefined" && matchMedia("(hover: hover) and (pointer: fine)").matches;
export const useDesktop = mouse;
// the wide LAYOUT (sidebar, card grid) is a width-only switch
export const useWide = () => useWindowDimensions().width >= 1000;

// ---- dropdown menu ----------------------------------------------------------------------------
export type MenuItem = { label: string; sub?: string; danger?: boolean; disabled?: boolean; checked?: boolean; onClick: () => void };
type Rect = { x: number; y: number; w: number; h: number };
type MenuState = { anchor: Rect; items: MenuItem[]; width?: number; onClose?: () => void } | null;
let menu: MenuState = null;
const menuListeners = new Set<() => void>();
const setMenu = (m: MenuState) => { const prev = menu; menu = m; menuListeners.forEach((l) => l()); if (!m) prev?.onClose?.(); };
const useMenu = () => useSyncExternalStore((l) => { menuListeners.add(l); return () => menuListeners.delete(l); }, () => menu);
export const closeMenu = () => setMenu(null);
/** Open a dropdown under the view `ref` points at. */
export function openMenu(ref: RNView | null, items: MenuItem[], opts: { width?: number; onClose?: () => void } = {}) {
  if (!ref) return;
  ref.measureInWindow((x, y, w, h) => setMenu({ anchor: { x, y, w, h }, items, ...opts }));
}

function MenuHost() {
  const m = useMenu(), t = useTheme(), win = useWindowDimensions();
  const [h, setH] = useState(0);
  useEffect(() => { setH(0); }, [m]);
  useEffect(() => {
    if (!m || !isWeb) return;
    // with a keyboard: the first item has the focus, arrows move, Enter picks, Esc / Tab close
    const items = () => [...document.querySelectorAll<HTMLElement>('#menu [role=menuitem]:not([aria-disabled=true])')];
    if (mouse()) requestAnimationFrame(() => items()[0]?.focus({ preventScroll: true }));
    const key = (e: KeyboardEvent) => {
      const its = items(), i = its.indexOf(document.activeElement as HTMLElement);
      const go = (n: number) => { e.preventDefault(); its[(n + its.length) % its.length]?.focus(); };
      if (e.key === "Escape" || e.key === "Tab") { if (e.key === "Escape") e.preventDefault(); closeMenu(); }
      else if (e.key === "ArrowDown") go(i + 1);
      else if (e.key === "ArrowUp") go(i < 0 ? -1 : i - 1);
      else if ((e.key === "Enter" || e.key === " ") && i >= 0) { e.preventDefault(); its[i].click(); }
    };
    window.addEventListener("keydown", key); return () => window.removeEventListener("keydown", key);
  }, [m]);
  if (!m) return null;
  const touch = !mouse();
  const w = Math.min(m.width || (touch ? 260 : 240), win.width - 16);
  const below = win.height - (m.anchor.y + m.anchor.h) - 12, above = m.anchor.y - 12;
  const up = h > below && above > below && h <= above;
  const left = Math.max(8, Math.min(m.anchor.x, win.width - w - 8));
  const top = up ? m.anchor.y - 4 - h : m.anchor.y + m.anchor.h + 4;
  return (
    <View style={{ position: "absolute", left: 0, top: 0, right: 0, bottom: 0, zIndex: 1040 }}>
      <Pressable accessibilityLabel="Close menu" style={{ position: "absolute", left: 0, top: 0, right: 0, bottom: 0 }} onPress={closeMenu} />
      <View {...ids("menu")} accessibilityRole="menu" onLayout={(e) => setH(e.nativeEvent.layout.height)}
        style={{ position: "absolute", left, top, width: w, opacity: h ? 1 : 0, padding: 4, backgroundColor: t.panel, borderWidth: 1, borderColor: t.gray.a[6], borderRadius: radius[4] }}>
        {m.items.map((it, i) => (
          <Pressable key={i} {...ids("menu-" + it.label.toLowerCase().replace(/[^a-z0-9]+/g, "-"))} accessibilityRole="menuitem" disabled={it.disabled} onPress={() => { setMenu(null); it.onClick(); }}
            style={({ pressed, hovered }: any) => [{ paddingHorizontal: touch ? 12 : 10, paddingVertical: touch ? 12 : 8, borderRadius: radius[2], opacity: it.disabled ? 0.5 : 1, backgroundColor: pressed ? t.gray.a[3] : hovered ? t.accent.a[3] : "transparent", flexDirection: "row", gap: 8 }]}>
            <View style={{ flex: 1 }}>
              <Text size={2} weight="medium" data={{ label: "1" }} style={{ color: it.danger ? t.c.red.a[11] : t.gray[12] }}>{it.label}</Text>
              {it.sub ? <Text size={1} color="gray">{it.sub}</Text> : null}
            </View>
            {it.checked ? <Text size={2} style={{ color: t.accent.a[11] }}>✓</Text> : null}
          </Pressable>
        ))}
      </View>
    </View>
  );
}

// the dialog rides above the keyboard in the app; the browser has no keyboard frame to follow
// (and the web fallback of KeyboardAvoidingView pushed the dialog 12 px off centre). It needs
// `behavior`: without one KeyboardAvoidingView is a plain View and the keyboard covers the dialog.
const Rise: any = isWeb ? View : KeyboardAvoidingView;

// ---- the yes/no question ---------------------------------------------------------------------
// With `input` (store.askText) it also has a text box; with `input.match` the box is one line and the
// action stays disabled until it holds exactly that text. A tap on the dimmed page cancels. The dialog
// rides above the keyboard.
function ConfirmHost() {
  const c = useStore((s) => s.confirm), t = useTheme(), ins = useSafeAreaInsets();
  const [text, setText] = useState("");
  useEffect(() => { setText(""); }, [c?.id]);
  const blocked = !!c && c.input?.match !== undefined && text.trim() !== c.input.match.trim();
  const cur = useRef(c); cur.current = c;
  useEffect(() => {
    if (!c || !isWeb) return;
    const key = (e: KeyboardEvent) => {
      // a held Enter that opened this must not auto-repeat straight into its action button
      if (e.repeat && e.key === "Enter") { e.preventDefault(); e.stopPropagation(); return; }
      if (e.key === "Escape") { e.preventDefault(); answer(false); return; }
      const tag = (e.target as HTMLElement)?.tagName;
      if ((e.target as HTMLElement)?.getAttribute?.("role") === "button") return; // Enter on Cancel is Cancel
      if (e.key === "Enter" && !(e as any).isComposing) {
        if (tag === "TEXTAREA" && !(e.metaKey || e.ctrlKey)) return;
        const q = cur.current; if (!q) return;
        const box = document.getElementById("ask-text") as HTMLInputElement | null;
        const v = box?.value || "";
        if (q.input?.match !== undefined && v.trim() !== q.input.match.trim()) return;
        e.preventDefault(); answer(true, v);
      }
    };
    window.addEventListener("keydown", key, true);
    // with a keyboard the text box (or else the action) has the focus, and it goes back afterwards;
    // on a phone nothing is focused, so the keyboard does not cover the question
    const before = document.activeElement as HTMLElement | null;
    if (mouse()) requestAnimationFrame(() => document.getElementById(c.input ? "ask-text" : "ask-ok")?.focus());
    return () => { window.removeEventListener("keydown", key, true); if (before?.isConnected && mouse()) before.focus({ preventScroll: true }); };
  }, [c?.id]);
  if (!c) return null;
  return (
    <View style={{ position: "absolute", left: 0, top: 0, right: 0, bottom: 0, zIndex: 1070 }}>
      <Pressable accessibilityLabel="Cancel" onPress={() => answer(false)} style={{ position: "absolute", left: 0, top: 0, right: 0, bottom: 0, backgroundColor: t.overlay }} />
      <Rise behavior="padding" style={{ flex: 1, justifyContent: "center", alignItems: "center", padding: 24, paddingTop: 24 + ins.top }} pointerEvents="box-none">
        <View {...ids("dialog")} accessibilityRole="alert" accessibilityViewIsModal
          style={{ width: "100%", maxWidth: 460, maxHeight: "100%", backgroundColor: t.panel, borderWidth: 1, borderColor: t.gray.a[6], borderRadius: radius[5] }}>
          <ScrollView contentContainerStyle={{ padding: 24 }} keyboardShouldPersistTaps="handled">
            <Heading size={4} mb={2}>{c.title}</Heading>
            {c.detail ? <P size={2} color="gray">{c.detail}</P> : null}
            {c.input && <>
              <Text size={2} weight="medium" mt={4} mb={1} style={{ color: t.gray[12] }}>{c.input.label}</Text>
              {c.input.match !== undefined
                ? <TextField id="ask-text" autoComplete="off" autoCapitalize="none" autoCorrect={false} placeholder={c.input.placeholder} value={text} onChangeText={setText}
                    returnKeyType="done" onSubmitEditing={() => { if (!blocked) answer(true, text); }} />
                : <TextArea id="ask-text" rows={4} maxLength={c.input.max} autoCapitalize="sentences" placeholder={c.input.placeholder} value={text} onChangeText={setText} />}
              {(c.input.note || (mouse() && c.input.match === undefined)) ? <P size={1} color="gray" mt={1}>{c.input.note ? c.input.note + " " : ""}{mouse() && c.input.match === undefined ? "⌘/Ctrl + Enter confirms." : ""}</P> : null}
            </>}
            <Flex justify="flex-end" gap={3} mt={5}>
              <Button variant="soft" color="gray" onPress={() => answer(false)}>Cancel</Button>
              <Button id="ask-ok" color={c.danger ? "red" : "blue"} disabled={blocked} onPress={() => answer(true, text)}>{c.action}</Button>
            </Flex>
          </ScrollView>
        </View>
      </Rise>
    </View>
  );
}

// ---- toasts ---------------------------------------------------------------------------------
function Toasts() {
  const toasts = useStore((s) => s.toasts), t = useTheme(), ins = useSafeAreaInsets(), desk = mouse();
  if (!toasts.length) return null;
  return (
    <View pointerEvents="box-none" accessibilityLiveRegion="polite"
      style={[{ position: "absolute", zIndex: 1100, gap: 8 }, desk ? { right: 24, bottom: 24, width: 420, maxWidth: "90%" } : { left: 16, right: 16, bottom: 16 + ins.bottom, alignItems: "center" }]}>
      {toasts.map((x) => {
        const color = x.kind === "error" ? "red" : x.kind === "ok" ? "green" : "gray";
        return (
          <Pressable key={x.id} onPress={() => dismissToast(x.id)} style={{ width: "100%", maxWidth: 600, backgroundColor: t.panel, borderRadius: radius[4] }}>
            <View {...ids(undefined, { toast: x.kind })} style={{ backgroundColor: t.c[color].a[2], borderWidth: 1, borderColor: t.c[color].a[6], borderRadius: radius[3], padding: 12 }}>
              <CalloutText color={color}>{x.text}</CalloutText>
            </View>
          </Pressable>
        );
      })}
    </View>
  );
}

export function OverlayHosts() {
  return <><MenuHost /><ConfirmHost /><Toasts /></>;
}
export type { ReactNode };
