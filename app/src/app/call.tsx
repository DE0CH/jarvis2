import { useLocalSearchParams } from "expo-router";
import { APICallPage, type APICallSpec } from "../pages/APICall";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<APICallSpec>(k);
  return p ? <APICallPage spec={p} /> : <Gone />;
}
