// React Native's Text and TextInput for the iPhone app, which runs inside the shell's ExtensionKit extension.
// In an app extension React Native has no UIApplication, so its font-size multiplier (RCTFontSizeMultiplier,
// read from UIApplication.preferredContentSizeCategory) comes out 0: every font size became 0, which iOS
// draws as its 12 pt default — all of Jarvis 2's text was one small size, unlike Jarvis 1. Here each text run
// takes its multiplier from the "body" Dynamic Type ramp instead (UIFontMetrics, which works in an extension):
// exactly 1.0 at the default text size, so sizes are the kit's (Jarvis 1's), and it still follows the
// iPhone's text size setting. Text fields don't scale (the kit's fields are a fixed 16 pt, as in Jarvis 1).
import { forwardRef, type ComponentProps, type ElementRef } from "react";
import { Text, TextInput as RNTextInput } from "react-native";

export const RNText = forwardRef<ElementRef<typeof Text>, ComponentProps<typeof Text>>(function RNText(p, ref) {
  return <Text dynamicTypeRamp="body" {...p} ref={ref} />;
});
export const TextInput = forwardRef<ElementRef<typeof RNTextInput>, ComponentProps<typeof RNTextInput>>(function TextInput(p, ref) {
  return <RNTextInput allowFontScaling={false} {...p} ref={ref} />;
});
