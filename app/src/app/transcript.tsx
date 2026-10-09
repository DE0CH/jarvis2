import { useLocalSearchParams } from "expo-router";
import { Transcript, type TranscriptSpec } from "../pages/Transcript";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<TranscriptSpec>(k);
  return p ? <Transcript spec={p} /> : <Gone />;
}
