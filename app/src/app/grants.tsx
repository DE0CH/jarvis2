import { useLocalSearchParams } from "expo-router";
import { GrantsPage, type GrantsSpec } from "../pages/Grants";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<GrantsSpec>(k);
  return p ? <GrantsPage spec={p} /> : <Gone />;
}
