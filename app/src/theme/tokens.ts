// The dashboard's look, ported from Radix Themes 3 with the settings the web dashboard used
// (radius "large", accent blue, gray slate, solid panels, light/dark from the OS). Sizes and colours
// were read off Radix's own rendered components (computed styles, light and dark), so the app and
// the web page look the same: same scales, same radii, same type ramp.
import * as rc from "@radix-ui/colors";

export type Scheme = "light" | "dark";
export type ColorName = "blue" | "gray" | "red" | "green" | "amber";
// steps 1–12 of a scale, and its alpha steps a1–a12
export type Scale = { [k: number]: string } & { a: { [k: number]: string } };

function scale(name: string, dark: boolean): Scale {
  const base = (rc as any)[name + (dark ? "Dark" : "")], alpha = (rc as any)[name + (dark ? "DarkA" : "A")];
  const s: any = { a: {} };
  for (let i = 1; i <= 12; i++) { s[i] = base[name + i]; s.a[i] = alpha[name + "A" + i]; }
  return s;
}
const SCALES: Record<ColorName, string> = { blue: "blue", gray: "slate", red: "red", green: "green", amber: "amber" };

export type Palette = {
  scheme: Scheme;
  c: Record<ColorName, Scale>;
  accent: Scale;
  gray: Scale;
  background: string;   // page background
  panel: string;        // cards, menus, dialogs (panelBackground "solid")
  surface: string;      // inside text fields, radio cards, the segmented control
  overlay: string;      // behind a dialog
  focus: string;
  // text on a solid (step 9) fill: white, except the bright scales where Radix uses dark text
  onSolid: (c: ColorName) => string;
};

export function palette(scheme: Scheme): Palette {
  const dark = scheme === "dark";
  const c = Object.fromEntries(Object.entries(SCALES).map(([k, n]) => [k, scale(n, dark)])) as Record<ColorName, Scale>;
  return {
    scheme, c, accent: c.blue, gray: c.gray,
    background: dark ? c.gray[1] : "#ffffff",
    panel: dark ? c.gray[2] : "#ffffff",
    surface: dark ? "rgba(0,0,0,0.25)" : "rgba(255,255,255,0.85)",
    overlay: dark ? "rgba(0,0,0,0.6)" : "rgba(0,0,0,0.4)",
    focus: dark ? c.blue[8] : c.blue[8],
    onSolid: (n) => (n === "amber" ? (dark ? c.gray[1] : "#21201c") : "#ffffff"),
  };
}

// scaling 1, radius factor 1.5 ("large")
export const space = { 1: 4, 2: 8, 3: 12, 4: 16, 5: 24, 6: 32, 7: 40, 8: 48, 9: 64 } as const;
export const radius = { 1: 4.5, 2: 6, 3: 9, 4: 12, 5: 18, 6: 24, full: 9999 } as const;
export const fontSize = { 1: 12, 2: 14, 3: 16, 4: 18, 5: 20, 6: 24, 7: 28, 8: 35, 9: 60 } as const;
export const lineHeight = { 1: 16, 2: 20, 3: 24, 4: 26, 5: 28, 6: 30, 7: 36, 8: 40, 9: 60 } as const;
// headings are set tighter than body text
export const headingLineHeight = { 1: 16, 2: 18, 3: 22, 4: 24, 5: 26, 6: 30, 7: 36, 8: 40, 9: 60 } as const;
export const letterSpacing = { 1: 0.0025, 2: 0, 3: 0, 4: -0.0025, 5: -0.005, 6: -0.00625, 7: -0.0075, 8: -0.01, 9: -0.025 } as const; // em
export type Size = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

export const fonts = {
  mono: "Menlo",
  monoWeb: "Menlo, Consolas, 'Bitstream Vera Sans Mono', monospace",
};
