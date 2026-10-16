import { useLocalSearchParams } from "expo-router";
import { LifecyclePage, type LogSpec } from "../pages/Logs";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<LogSpec>(k);
  return p ? <LifecyclePage spec={p} /> : <Gone />;
}
