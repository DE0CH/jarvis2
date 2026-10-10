import { useLocalSearchParams } from "expo-router";
import { SearchContext, type ContextSpec } from "../pages/SearchContext";
import { payloadOf } from "../ui/page";
import { Gone } from "../ui/gone";
export default function Route() {
  const { k } = useLocalSearchParams<{ k: string }>();
  const p = payloadOf<ContextSpec>(k);
  return p ? <SearchContext spec={p} /> : <Gone />;
}
