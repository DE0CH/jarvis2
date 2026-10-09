import { useLocalSearchParams } from "expo-router";
import { TaskDetail, type TaskSpec } from "../pages/TaskDetail";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<TaskSpec>(k);
  return p ? <TaskDetail spec={p} /> : <Gone />;
}
