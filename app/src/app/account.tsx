import { useLocalSearchParams } from "expo-router";
import { SwitchAccountPage, type SwitchAccountSpec } from "../pages/SwitchAccount";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<SwitchAccountSpec>(k);
  return p ? <SwitchAccountPage spec={p} /> : <Gone />;
}
