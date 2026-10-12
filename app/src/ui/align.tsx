import { createContext, useContext, type ReactNode } from "react";
import { View, type StyleProp, type ViewStyle } from "react-native";

// Rows that line up across the cards of one grid row (Deyao, 2026-10-12: "the rows should align across different
// cards"). Cards (cards.tsx) gives each card a scope; an Aligned part reports its natural height (measured on an
// inner view, so the stretch never feeds back) and takes the tallest height of the same part in its grid row.
// Outside a multi-column grid there is no scope and Aligned is a plain wrapper.
export type AlignScope = { heights: Record<string, number>; report: (part: string, h: number) => void };
export const AlignContext = createContext<AlignScope | null>(null);

export function Aligned({ part, children, style }: { part: string; children?: ReactNode; style?: StyleProp<ViewStyle> }) {
  const a = useContext(AlignContext);
  if (!a) return <View style={style}>{children}</View>;
  return (
    <View style={[{ minHeight: a.heights[part] }, style]}>
      <View onLayout={(e) => a.report(part, Math.ceil(e.nativeEvent.layout.height))}>{children}</View>
    </View>
  );
}
