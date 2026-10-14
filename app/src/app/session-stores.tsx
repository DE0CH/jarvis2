import { useLocalSearchParams } from "expo-router";
import { SessionStoresPage, type SessionStoresSpec } from "../pages/SessionStores";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<SessionStoresSpec>(k);
  return p ? <SessionStoresPage spec={p} /> : <Gone />;
}
