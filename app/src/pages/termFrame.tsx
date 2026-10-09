// The terminal's frame in the browser. It is sized to the VISUAL viewport, not the layout viewport —
// on iOS Safari the software keyboard shrinks only the former, so a plain fixed/100dvh panel keeps
// its input row hidden under the keys.
import { useEffect, useState, type ReactNode } from "react";
import { View } from "react-native";

function read() {
  const v = window.visualViewport;
  return v ? { top: Math.round(v.offsetTop), height: Math.round(v.height), kb: window.innerHeight - v.height > 120 } : { top: 0, height: window.innerHeight, kb: false };
}
function useVisualViewport() {
  const [vv, setVv] = useState(read);
  useEffect(() => {
    const v = window.visualViewport, on = () => setVv(read());
    v?.addEventListener("resize", on); v?.addEventListener("scroll", on); window.addEventListener("resize", on);
    return () => { v?.removeEventListener("resize", on); v?.removeEventListener("scroll", on); window.removeEventListener("resize", on); };
  }, []);
  return vv;
}
export function useTermFrame() {
  const vv = useVisualViewport();
  return { style: { position: "fixed", left: 0, right: 0, top: vv.top, height: vv.height, zIndex: 1060 } as any };
}
export function TermBody({ children }: { children: (kb: boolean) => ReactNode }) {
  const vv = useVisualViewport();
  return <View style={{ flex: 1 }}>{children(vv.kb)}</View>;
}
