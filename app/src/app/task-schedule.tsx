import { useLocalSearchParams } from "expo-router";
import { TaskScheduleEdit, type ScheduleSpec } from "../pages/TaskScheduleEdit";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<ScheduleSpec>(k);
  return p ? <TaskScheduleEdit spec={p} /> : <Gone />;
}
