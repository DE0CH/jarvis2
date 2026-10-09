// The list: a top bar (the tab's name on a wide screen, where the tabs are the sidebar), the banners,
// the tabs (narrow screens), and the tab's view. Pages open on top of it (ui/page.tsx) and it stays
// mounted underneath, so its scroll position is kept. No pull-to-refresh: the ↻ button refreshes, and
// coming back to the foreground refreshes by itself.
import { ScrollView, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useStore, setTab, refresh, TABS, type Tab } from "../lib/store";
import { sessionTitle, usd } from "../lib/api";
import { useTheme } from "../theme";
import { Button, Callout, Heading, IconButton, Spinner, Tabs } from "../ui/kit";
import { TopBar, openPage } from "../ui/page";
import { useWide } from "../ui/overlays";
import { Sessions } from "../views/Sessions";
import { Records } from "../views/Records";
import { Stores } from "../views/Stores";
import { Settings } from "../views/Settings";

function Banners() {
  const st = useStore((s) => s.state);
  const b = st.budget, dead = st.sessions.filter((m) => m.authFailed);
  return (
    <View nativeID="banners">
      {!!st.loadError && <Callout color="red" mb={3}>{"Can't reach the router: " + st.loadError}</Callout>}
      {st.loaded && !st.core.up && <Callout color="amber" mb={3}>The core is not answering — sessions can't be created, resumed or approved until it is back.</Callout>}
      {dead.length > 0 && <Callout color="red" mb={3} id="banner-creds">{`Claude's login failed in ${dead.length === 1 ? "“" + sessionTitle(dead[0]) + "”" : dead.length + " sessions"}. The router writes Jarvis 1's credentials into a session whose login expired; if this stays, re-login in Jarvis 1's Settings.`}</Callout>}
      {b?.capped ? <Callout color="red" mb={3} id="banner-budget">{`Fly spend reached the ${usd(b.capUsd)} cap for ${b.month} (${usd(b.spentUsd)}): the router paused every running session.`}</Callout>
        : b?.warned ? <Callout color="amber" mb={3} id="banner-budget">{`Fly spend this month: ${usd(b.spentUsd)} of the ${usd(b.capUsd)} cap. At the cap every running session is paused.`}</Callout> : null}
      {!!st.fly?.error && st.fly.error !== "FLY_READ_TOKEN not set" && <Callout color="red" mb={3}>{"Fly: " + st.fly.error}</Callout>}
    </View>
  );
}

export default function Dashboard() {
  const t = useTheme(), ins = useSafeAreaInsets(), wide = useWide();
  const tab = useStore((s) => s.tab);
  const refreshing = useStore((s) => s.refreshing);
  return (
    <View style={{ flex: 1, backgroundColor: t.background }}>
      <TopBar max={wide ? 1320 : 820}>
        <Heading size={4} lines={1} style={{ flex: 1, minWidth: 0 }}>{wide ? TABS.find(([k]) => k === tab)![1] : "Jarvis 2"}</Heading>
        <IconButton id="refreshBtn" variant="soft" color="gray" label="Refresh" onPress={() => refresh(true)}>{refreshing ? <Spinner /> : "↻"}</IconButton>
        {tab === "sessions" && <Button id="newBtn" onPress={() => openPage("new")}>+ New session</Button>}
      </TopBar>
      <ScrollView keyboardShouldPersistTaps="handled" contentContainerStyle={{ paddingBottom: 24 + ins.bottom }}>
        <View style={{ width: "100%", maxWidth: wide ? 1320 : 820, alignSelf: "center", paddingHorizontal: wide ? 32 : 16, paddingTop: 16 }}>
          <Banners />
          {!wide && <Tabs value={tab} onChange={(v) => setTab(v as Tab)} items={TABS} />}
          <View nativeID={"view-" + tab}>
            {tab === "sessions" && <Sessions />}
            {tab === "stores" && <Stores />}
            {tab === "records" && <Records />}
            {tab === "settings" && <Settings />}
          </View>
        </View>
      </ScrollView>
    </View>
  );
}
