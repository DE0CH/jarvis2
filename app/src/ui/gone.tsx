import { useEffect } from "react";
import { router } from "expo-router";
// a page whose payload is gone (the browser reloaded on it): back to the list
export function Gone() {
  useEffect(() => { router.replace("/"); }, []);
  return null;
}
