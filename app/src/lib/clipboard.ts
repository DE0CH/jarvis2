// Copying to the clipboard, web: the browser's async clipboard (needs a secure context — the router's https
// page). The iOS app is native SwiftUI (ios/) and copies with UIPasteboard itself.
export const canCopy = typeof navigator !== "undefined" && !!(navigator as any).clipboard?.writeText;
export async function copyText(text: string): Promise<void> {
  if (!canCopy) throw new Error("this browser has no clipboard access");
  await (navigator as any).clipboard.writeText(text);
}
