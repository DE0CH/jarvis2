// The core this app is paired with, and the shell's pairing page (the app only).
import { useStore } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Button, Card, Flex, Heading, Muted, P } from "../ui/kit";
import { Cards } from "../ui/cards";

const short = (k?: string) => (k ? k.slice(0, 16) + "…" + k.slice(-8) : "—");
export function Settings() {
  const core = useStore((s) => s.state.core);
  return (
    <Cards>
      <Card data={{ settings: "core" }}>
        <Heading size={3} mb={1}>Core</Heading>
        <Muted>{core.up ? "Answering." : "Not answering."}</Muted>
        <P size={2} mt={2}>Signing key</P>
        <P size={1} mono color="gray" selectable>{short(core.signingKey)}</P>
        <P size={2} mt={1}>Agreement key</P>
        <P size={1} mono color="gray" selectable>{short(core.agreementKey)}</P>
        <Muted mt={2}>As the router reports them. The app trusts only the core key pasted on its pairing page.</Muted>
      </Card>
      {hasShell && <Card data={{ settings: "pairing" }}>
        <Heading size={3} mb={1}>Pairing</Heading>
        <Muted>This iPhone's public keys and the core's key, on the shell's secure page.</Muted>
        <Flex mt={3}><Button id="open-pairing" variant="soft" onPress={() => requestSecure("pairing", {})}>Open pairing</Button></Flex>
      </Card>}
    </Cards>
  );
}
