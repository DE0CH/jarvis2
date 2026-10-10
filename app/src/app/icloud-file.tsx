import { useLocalSearchParams } from "expo-router";
import { IcloudFile, type IcloudFileSpec } from "../pages/IcloudFile";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<IcloudFileSpec>(k);
  return p ? <IcloudFile spec={p} /> : <Gone />;
}
