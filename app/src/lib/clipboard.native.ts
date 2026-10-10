// Copying to the clipboard, app: this UI runs in the shell's ExtensionKit extension, which carries no
// clipboard module of its own, so it asks the shell (ShellBridge.copyText → XPC HostService.copyText), whose
// process is the foreground app and writes UIPasteboard. Plain text only; the shell caps the length.
import { NativeModules } from "react-native";

const bridge = NativeModules.ShellBridge as undefined | { copyText?: (text: string) => void };
export const canCopy = !!bridge?.copyText;
export async function copyText(text: string): Promise<void> {
  if (!bridge?.copyText) throw new Error("no shell");
  bridge.copyText(text);
}
