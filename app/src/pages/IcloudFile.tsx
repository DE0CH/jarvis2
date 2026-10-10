// One iCloud Drive file as the index read it (api/icloud/file, forwarded to Jarvis 1's icloud-index): its path
// (with Copy — a session fetches it with `rclone copy "icloud:<path>" …`), what kind it is, and the text taken
// from it (document text, OCR, video frames, speech), each part labelled where it came from.
import { useEffect, useState } from "react";
import { api, type IcloudFile as File } from "../lib/api";
import { Marked, bytes } from "../views/Search";
import { CopyButton } from "../ui/bits";
import { Box, Card, Flex, Lbl, Muted, P, Spinner } from "../ui/kit";
import { Page } from "../ui/page";

export type IcloudFileSpec = { path: string; terms: string[] };

export function IcloudFile({ spec }: { spec: IcloudFileSpec }) {
  const [f, setF] = useState<File | null>(null), [err, setErr] = useState("");
  useEffect(() => {
    let live = true;
    api<File>("GET", "api/icloud/file?" + new URLSearchParams({ path: spec.path })).then((j) => { if (live) setF(j); }, (e) => { if (live) setErr(e.message); });
    return () => { live = false; };
  }, [spec.path]);
  const name = spec.path.split("/").pop() || spec.path;
  return (
    <Page title={name} id="icloud-file-page">
      <Flex gap={2} align="center" mt={2}>
        <P size={1} mono color="gray" selectable style={{ flex: 1 }}>{spec.path}</P>
        <CopyButton id="if-copy-path" value={spec.path} what="Path" />
      </Flex>
      {err ? <P size={2} color="red" mt={3}>{err}</P>
        : !f ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Reading…</P></Flex>
        : <>
            <Muted mt={1}>{[f.kind, f.size != null ? bytes(f.size) : "", f.mtime ? "modified " + f.mtime.slice(0, 10) : "", f.state && f.state !== "done" ? f.state : "", f.note].filter(Boolean).join(" · ")}</Muted>
            {!!f.error && <P size={2} color="red" mt={1}>{f.error}</P>}
            <Lbl>What the index read</Lbl>
            {!(f.chunks || []).length ? <Muted>Nothing yet.</Muted>
              : (f.chunks || []).map((c, i) => (
                <Box key={i} mb={3}>
                  {!!(c.part || c.src) && <P size={1} weight="bold" color="gray" upper>{[c.part, c.src].filter(Boolean).join(" · ")}</P>}
                  <Card size={1} variant="surface"><P size={2} selectable><Marked text={c.text} terms={spec.terms} /></P></Card>
                </Box>))}
          </>}
    </Page>
  );
}
