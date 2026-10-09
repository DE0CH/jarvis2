// The core as the router reports it, and the shell's recovery and master-key pages (the app only).
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
        <Muted mt={2}>As the router reports them. The app trusts only the core it recovered (its 8 words checked against the box key in git).</Muted>
      </Card>
      {hasShell && <Card data={{ settings: "recovery" }}>
        <Heading size={3} mb={1}>Recovery</Heading>
        <Muted>A new or restarted core gets every store back from the backups: its 8 words, then the master key and the bucket's read keys from your password manager.</Muted>
        <Flex mt={3}><Button id="open-recovery" variant="soft" onPress={() => requestSecure("recovery", {})}>Open recovery</Button></Flex>
      </Card>}
      {hasShell && <Card data={{ settings: "master-key" }}>
        <Heading size={3} mb={1}>Master key</Heading>
        <Muted>First setup only: make the master key pair on this iPhone. The private half goes to your password manager, the public half into the repo.</Muted>
        <Flex mt={3}><Button id="open-master-key" variant="soft" color="gray" onPress={() => requestSecure("master-key", {})}>Make a master key pair…</Button></Flex>
      </Card>}
    </Cards>
  );
}
