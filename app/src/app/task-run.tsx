import { useLocalSearchParams } from "expo-router";
import { TaskRunPage, type TaskRunSpec } from "../pages/TaskRun";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<TaskRunSpec>(k);
  return p ? <TaskRunPage spec={p} /> : <Gone />;
}
