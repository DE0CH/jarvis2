import { useLocalSearchParams } from "expo-router";
import { LifecycleOpPage, type OpSpec } from "../pages/Logs";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<OpSpec>(k);
  return p ? <LifecycleOpPage spec={p} /> : <Gone />;
}
