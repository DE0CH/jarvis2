import { useLocalSearchParams } from "expo-router";
import { ContentStore, type ContentSpec } from "../pages/ContentStore";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<ContentSpec>(k);
  return p ? <ContentStore spec={p} /> : <Gone />;
}
