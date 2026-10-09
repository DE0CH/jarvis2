// The terminal's frame in the app: everything below the title bar rides the keyboard frame by frame
// (react-native-keyboard-controller follows the keyboard's own animation curve), so the input bar
// sits on top of the keys while they slide in and out, and xterm's area shrinks to what is left.
import type { ReactNode } from "react";
import { View } from "react-native";
import { KeyboardAvoidingView, useKeyboardState } from "react-native-keyboard-controller";

export function TermBody({ children }: { children: (kb: boolean) => ReactNode }) {
  const kb = useKeyboardState((s) => s.isVisible);
  return <KeyboardAvoidingView behavior="padding" style={{ flex: 1 }}><View style={{ flex: 1 }}>{children(kb)}</View></KeyboardAvoidingView>;
}
export const useTermFrame = () => ({ style: { flex: 1 } as const });
