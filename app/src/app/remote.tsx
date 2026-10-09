import { useLocalSearchParams } from "expo-router";
import { Remote, type RemoteSpec } from "../pages/Remote";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<RemoteSpec>(k);
  return p ? <Remote spec={p} /> : <Gone />;
}
