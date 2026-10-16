import { useLocalSearchParams } from "expo-router";
import { SessionLogPage, type LogSpec } from "../pages/Logs";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<LogSpec>(k);
  return p ? <SessionLogPage spec={p} /> : <Gone />;
}
