// Destroyed sessions (GET api/records): what each was, view only — a destroyed session's machine is
// burned, so nothing here can bring it back.
import { useEffect } from "react";
import { ago, HARNESS, sessionTitle, storesOf } from "../lib/api";
import { useStore, loadRecords } from "../lib/store";
import { Card, Flex, Heading, Muted, P, Pill, Spinner } from "../ui/kit";
import { Cards } from "../ui/cards";

export function Records() {
  const r = useStore((s) => s.records);
  const policy = useStore((s) => s.policy);
  useEffect(() => { loadRecords(); }, []);
  if (!r.loaded) return r.err ? <P size={2} color="red">{r.err}</P> : <Flex gap={2} align="center" mt={4}><Spinner /><Muted>Loading records…</Muted></Flex>;
  const list = [...r.items].sort((a, b) => String(b.destroyedAt || b.created || "").localeCompare(String(a.destroyedAt || a.created || "")));
  if (!list.length) return <P size={3} color="gray" align="center" mt={8} mb={8}>No destroyed sessions yet.</P>;
  return (
    <>
      {!!r.err && <P size={2} color="red" mb={2}>{r.err}</P>}
      <Cards>
        {list.map((m) => (
          <Card key={m.id} data={{ record: m.id }}>
            <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
              <Heading size={3} style={{ flex: 1 }}>{sessionTitle(m)}</Heading>
              <Pill kind="dim">destroyed</Pill>
            </Flex>
            <Muted>{[storesOf(m, policy).length ? "stores: " + storesOf(m, policy).join(", ") : "no stores", HARNESS[m.harness || ""] || m.harness, m.model].filter(Boolean).join(" · ")}</Muted>
            <Muted>{[m.created ? "created " + ago(m.created) : "", m.destroyedAt ? "destroyed " + ago(m.destroyedAt) : ""].filter(Boolean).join(" · ")}</Muted>
          </Card>
        ))}
      </Cards>
    </>
  );
}
