import { useLocalSearchParams } from "expo-router";
import { TerminalPage, type TermSpec } from "../pages/Terminal";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<TermSpec>(k);
  return p ? <TerminalPage spec={p} /> : <Gone />;
}
