import { useLocalSearchParams } from "expo-router";
import { TaskEdit, type TaskEditSpec } from "../pages/TaskEdit";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<TaskEditSpec>(k);
  return p ? <TaskEdit spec={p} /> : <Gone />;
}
