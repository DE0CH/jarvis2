// Browser-only setup. iOS Safari ignores user-scalable=no in a normal tab (honoured only when added
// to the Home Screen), so pinch-zoom is blocked by hand: cancel multi-finger touchmove and the
// gesture events.
if (typeof document !== "undefined") {
  const opts = { passive: false } as AddEventListenerOptions;
  document.addEventListener("touchmove", (e: any) => { if ((e.scale !== undefined && e.scale !== 1) || e.touches.length > 1) e.preventDefault(); }, opts);
  for (const n of ["gesturestart", "gesturechange", "gestureend"]) document.addEventListener(n, (e) => e.preventDefault(), opts);
}
export {};
