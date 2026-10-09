import { useLocalSearchParams } from "expo-router";
import { SchedulesPage, type SchedulesSpec } from "../pages/Schedules";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<SchedulesSpec>(k);
  return p ? <SchedulesPage spec={p} /> : <Gone />;
}
