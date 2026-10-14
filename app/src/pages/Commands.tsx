// The commands Deyao approved for a session (docs/API.md "Approvals", kind `command`): each ran once under its
// grant; the router keeps the last 10 results on the session (`commands`, newest last).
import { sessionTitle, ago } from "../lib/api";
import { useStore } from "../lib/store";
import { Card, Flex, Heading, Muted, Pill, Quote, Row, Rows } from "../ui/kit";
import { Cards } from "../ui/cards";
import { Page } from "../ui/page";

export type CommandsSpec = { id: string };

export function CommandsPage({ spec }: { spec: CommandsSpec }) {
  const m = useStore((s) => s.state.sessions.find((x) => x.id === spec.id));
  const list = [...(m?.commands || [])].reverse();
  return (
    <Page title="Command results" id="commands-page">
      <Rows mt={2}><Row label="Session" id="cmd-session">{m ? sessionTitle(m) : spec.id}</Row></Rows>
      {!list.length ? <Muted mt={4}>None yet.</Muted> : <Cards mt={12}>
        {list.map((c, i) => (
          <Card key={c.approval + i} data={{ command: c.approval }}>
            <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
              <Heading size={3} style={{ flex: 1 }} lines={2}>{c.cmd}</Heading>
              {c.error || c.code !== 0 ? <Pill kind="bad">{c.error ? "refused" : "exit " + c.code}</Pill> : <Pill kind="ok">exit 0</Pill>}
            </Flex>
            <Rows><Row label="Ran">{ago(c.at)}</Row>{!!c.error && <Row label="Error" color="red">{c.error}</Row>}</Rows>
            {!!c.stdout && <Quote by="stdout" lines={12}>{c.stdout}</Quote>}
            {!!c.stderr && <Quote by="stderr" color="amber" lines={12}>{c.stderr}</Quote>}
          </Card>))}
      </Cards>}
    </Page>
  );
}
