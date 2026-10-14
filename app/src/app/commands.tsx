import { useLocalSearchParams } from "expo-router";
import { CommandsPage, type CommandsSpec } from "../pages/Commands";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<CommandsSpec>(k);
  return p ? <CommandsPage spec={p} /> : <Gone />;
}
