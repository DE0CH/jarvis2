import { Children, cloneElement, isValidElement, useCallback, useState, type ReactNode } from "react";
import { View } from "react-native";
import { useWide } from "./overlays";
import { AlignContext } from "./align";

// A list of cards: one column, and on a wide screen a grid of ≥340 px columns filling the width.
// Cards in a row share its height (their actions sit on the bottom edge).
export function Cards({ children, mt }: { children: ReactNode; mt?: number }) {
  const wide = useWide();
  const [w, setW] = useState(0);
  const cols = wide && w ? Math.max(1, Math.floor((w + 12) / (340 + 12))) : 1;
  const cw = cols > 1 ? (w - 12 * (cols - 1)) / cols : undefined;
  // each card's parts' natural heights, by card key then part (align.tsx); a grid row takes the tallest of each part
  const [nat, setNat] = useState<Record<string, Record<string, number>>>({});
  const report = useCallback((card: string, part: string, h: number) =>
    setNat((n) => (n[card]?.[part] === h ? n : { ...n, [card]: { ...n[card], [part]: h } })), []);
  const items = Children.toArray(children).filter(Boolean);
  const keyOf = (c: ReactNode, i: number) => String(isValidElement(c) && c.key != null ? c.key : i);
  return (
    <View onLayout={(e) => setW(e.nativeEvent.layout.width)} style={{ flexDirection: cols > 1 ? "row" : "column", flexWrap: cols > 1 ? "wrap" : undefined, gap: 12, marginTop: mt }}>
      {items.map((c, i) => {
        const k = keyOf(c, i);
        const card = cols > 1 && isValidElement(c) ? cloneElement(c as any, { style: [(c.props as any).style, { flexGrow: 1 }] }) : c;
        if (cols <= 1) return <View key={k}>{card}</View>;
        const row = items.slice(i - (i % cols), i - (i % cols) + cols).map(keyOf);
        const heights: Record<string, number> = {};
        for (const m of row) for (const [part, h] of Object.entries(nat[m] || {})) heights[part] = Math.max(heights[part] || 0, h);
        return (
          <View key={k} style={{ width: cw }}>
            <AlignContext.Provider value={{ heights, report: (part, h) => report(k, part, h) }}>{card}</AlignContext.Provider>
          </View>);
      })}
    </View>
  );
}
