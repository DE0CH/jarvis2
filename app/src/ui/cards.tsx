import { Children, cloneElement, isValidElement, useState, type ReactNode } from "react";
import { View } from "react-native";
import { useWide } from "./overlays";

// A list of cards: one column, and on a wide screen a grid of ≥340 px columns filling the width.
// Cards in a row share its height (their actions sit on the bottom edge).
export function Cards({ children, mt }: { children: ReactNode; mt?: number }) {
  const wide = useWide();
  const [w, setW] = useState(0);
  const cols = wide && w ? Math.max(1, Math.floor((w + 12) / (340 + 12))) : 1;
  const cw = cols > 1 ? (w - 12 * (cols - 1)) / cols : undefined;
  return (
    <View onLayout={(e) => setW(e.nativeEvent.layout.width)} style={{ flexDirection: cols > 1 ? "row" : "column", flexWrap: cols > 1 ? "wrap" : undefined, gap: 12, marginTop: mt }}>
      {Children.toArray(children).filter(Boolean).map((c, i) => (
        <View key={isValidElement(c) && c.key != null ? c.key : i} style={cw ? { width: cw } : undefined}>
          {cols > 1 && isValidElement(c) ? cloneElement(c as any, { style: [(c.props as any).style, { flexGrow: 1 }] }) : c}
        </View>))}
    </View>
  );
}
