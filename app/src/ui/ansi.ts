// A tmux pane capture with escapes (`capture-pane -p -e`) → lines of styled runs, drawn as plain React
// Native Text (no xterm.js / WebView: the app's React Native runs in the shell's extension, which carries no
// WebView). Only SGR (colours, bold, dim, italic, underline, inverse) appears in a capture; anything else
// is dropped. The cursor cell is drawn inverted.
export type Style = { fg?: string; bg?: string; bold?: boolean; dim?: boolean; italic?: boolean; underline?: boolean; inverse?: boolean };
export type Run = { text: string; style: Style };

// xterm's default 16 colours (dark background)
const BASE = ["#000000", "#cd3131", "#0dbc79", "#e5e510", "#2472c8", "#bc3fbc", "#11a8cd", "#e5e5e5",
  "#666666", "#f14c4c", "#23d18b", "#f5f543", "#3b8eea", "#d670d6", "#29b8db", "#ffffff"];
export const TERM_FG = "#d4d4d4", TERM_BG = "#0b0d11";
const hex2 = (n: number) => n.toString(16).padStart(2, "0");
function c256(n: number): string {
  if (n < 16) return BASE[n];
  if (n >= 232) { const v = 8 + (n - 232) * 10; return "#" + hex2(v) + hex2(v) + hex2(v); }
  const i = n - 16, l = [0, 95, 135, 175, 215, 255];
  return "#" + hex2(l[Math.floor(i / 36)]) + hex2(l[Math.floor(i / 6) % 6]) + hex2(l[i % 6]);
}

function sgr(st: Style, params: number[]): Style {
  const s = { ...st };
  if (!params.length) params = [0];
  for (let i = 0; i < params.length; i++) {
    const p = params[i];
    if (p === 0) { for (const k of Object.keys(s)) delete (s as any)[k]; }
    else if (p === 1) s.bold = true;
    else if (p === 2) s.dim = true;
    else if (p === 3) s.italic = true;
    else if (p === 4) s.underline = true;
    else if (p === 7) s.inverse = true;
    else if (p === 22) { s.bold = false; s.dim = false; }
    else if (p === 23) s.italic = false;
    else if (p === 24) s.underline = false;
    else if (p === 27) s.inverse = false;
    else if (p >= 30 && p <= 37) s.fg = BASE[p - 30];
    else if (p >= 90 && p <= 97) s.fg = BASE[p - 90 + 8];
    else if (p === 39) delete s.fg;
    else if (p >= 40 && p <= 47) s.bg = BASE[p - 40];
    else if (p >= 100 && p <= 107) s.bg = BASE[p - 100 + 8];
    else if (p === 49) delete s.bg;
    else if ((p === 38 || p === 48) && params[i + 1] === 5) { const c = c256(params[i + 2] ?? 0); if (p === 38) s.fg = c; else s.bg = c; i += 2; }
    else if ((p === 38 || p === 48) && params[i + 1] === 2) {
      const c = "#" + hex2(params[i + 2] ?? 0) + hex2(params[i + 3] ?? 0) + hex2(params[i + 4] ?? 0);
      if (p === 38) s.fg = c; else s.bg = c; i += 4;
    }
  }
  return s;
}

const same = (a: Style, b: Style) => a.fg === b.fg && a.bg === b.bg && !!a.bold === !!b.bold && !!a.dim === !!b.dim && !!a.italic === !!b.italic && !!a.underline === !!b.underline && !!a.inverse === !!b.inverse;

/** the screen as lines of runs; `cursor` [x, y] marks that cell inverted */
export function parseScreen(screen: string, cursor?: [number, number] | null): Run[][] {
  const lines = screen.replace(/\r/g, "").split("\n");
  let st: Style = {};
  return lines.map((line, y) => {
    const cells: { ch: string; style: Style }[] = [];
    const re = /\x1b\[([0-9;:]*)([A-Za-z])|\x1b[\]P_^][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b./g;
    let last = 0, m: RegExpExecArray | null;
    const push = (text: string) => { for (const ch of Array.from(text)) cells.push({ ch, style: st }); };
    while ((m = re.exec(line))) {
      push(line.slice(last, m.index));
      if (m[2] === "m") st = sgr(st, (m[1] || "").split(/[;:]/).filter((x) => x !== "").map((x) => parseInt(x, 10) || 0));
      last = re.lastIndex;
    }
    push(line.slice(last));
    if (cursor && cursor[1] === y) {
      while (cells.length <= cursor[0]) cells.push({ ch: " ", style: {} });
      const c = cells[cursor[0]];
      cells[cursor[0]] = { ch: c.ch, style: { ...c.style, inverse: !c.style.inverse } };
    }
    const runs: Run[] = [];
    for (const c of cells) {
      const r = runs[runs.length - 1];
      if (r && same(r.style, c.style)) r.text += c.ch; else runs.push({ text: c.ch, style: c.style });
    }
    return runs;
  });
}

/** a run's colours for drawing (inverse swaps them; dim halves the foreground) */
export function colours(s: Style): { color: string; backgroundColor?: string } {
  let fg = s.fg || TERM_FG, bg = s.bg;
  if (s.inverse) { const f = fg; fg = bg || TERM_BG; bg = f; }
  return { color: s.dim && fg.length === 7 ? fg + "99" : fg, backgroundColor: bg };
}
