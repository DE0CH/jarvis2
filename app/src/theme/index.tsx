import { createContext, useContext, useMemo, type ReactNode } from "react";
import { useColorScheme } from "react-native";
import { palette, type Palette, type Scheme } from "./tokens";

export * from "./tokens";

// The OS appearance, unless a subtree forces one (the terminal is always dark).
const Forced = createContext<Scheme | null>(null);

export function useTheme(): Palette {
  const forced = useContext(Forced);
  const os = useColorScheme() === "dark" ? "dark" : "light";
  const scheme = forced ?? os;
  return useMemo(() => palette(scheme), [scheme]);
}

export function ForceScheme({ scheme, children }: { scheme: Scheme; children: ReactNode }) {
  return <Forced.Provider value={scheme}>{children}</Forced.Provider>;
}
