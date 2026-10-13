// One content store's files (GET api/content/:name/files): download, delete, upload (web: a file picker; the file goes
// in as it is, 25 MB at most, under its own name or a folder path typed before it), and deleting the whole store.
import { useEffect, useState } from "react";
import { Platform } from "react-native";
import { api, downloadContent, uploadContent } from "../lib/api";
import { ask, askText, failed, toast, exclusive, pend, useStore } from "../lib/store";
import { Button, Card, Flex, Heading, Muted, P, Row, Rows, Spinner, Text, TextField } from "../ui/kit";
import { Page, closePage } from "../ui/page";
import { fmtBytes } from "../views/Content";

type File = { path: string; size: number; modified: string };
export type ContentSpec = { name: string; changed?: () => void };

export function ContentStore({ spec }: { spec: ContentSpec }) {
  const name = spec.name;
  const [files, setFiles] = useState<File[] | null>(null), [err, setErr] = useState<string | null>(null), [folder, setFolder] = useState("");
  const pending = useStore((s) => s.pending);
  async function load() {
    try { setFiles((await api<{ files: File[] }>("GET", `api/content/${name}/files`)).files || []); setErr(null); }
    catch (e: any) { setErr(e.message); }
  }
  useEffect(() => { load(); }, [name]);
  function pick() {
    const input = document.createElement("input");
    input.type = "file"; input.multiple = true;
    input.onchange = () => upload(Array.from(input.files || []));
    input.click();
  }
  const upload = (list: globalThis.File[]) => exclusive("content-up:" + name, async () => {
    const dir = folder.trim().replace(/^\/+|\/+$/g, "");
    for (const [i, f] of list.entries()) {
      if (f.size > 25 << 20) { toast(f.name + ": larger than 25 MB, skipped.", "error"); continue; }
      pend("content-up:" + name, `Uploading ${i + 1}/${list.length}…`);
      try { await uploadContent(name, (dir ? dir + "/" : "") + f.name, f); } catch (e) { failed(e); break; }
    }
    pend("content-up:" + name, null);
    await load(); spec.changed?.();
  });
  const del = (f: File) => exclusive("content-f:" + name + f.path, async () => {
    if (!(await ask({ title: "Delete file?", rows: [{ label: "Store", value: name }, { label: "File", value: f.path }], action: "Delete", danger: true }))) return;
    try { await api("DELETE", `api/content/${name}/file?path=${encodeURIComponent(f.path)}`); await load(); spec.changed?.(); } catch (e) { failed(e); }
  });
  const delStore = () => exclusive("content-del:" + name, async () => {
    const ok = await askText({ title: "Delete content store?", danger: true, action: "Delete store",
      rows: [{ label: "Store", value: name }, { label: "Files", value: String(files?.length ?? "?") }],
      detail: "Every file in it goes. Sessions started with it get an empty folder.",
      input: { heading: "Delete store", label: "Type the store's name to confirm", placeholder: name, match: name } });
    if (ok === null) return;
    try { await api("DELETE", `api/content/${name}`); toast("Deleted " + name + ".", "ok"); spec.changed?.(); closePage(); } catch (e) { failed(e); }
  });
  const busy = pending.get("content-up:" + name);
  return (
    <Page title={name} right={Platform.OS === "web" ? <Button id="content-upload" disabled={!!busy} onPress={pick}>{busy ? <><Spinner /><Text size={2}>{busy}</Text></> : "Upload"}</Button> : undefined}>
      {Platform.OS === "web" && <>
        <Muted>Folder for uploads (optional)</Muted>
        <TextField id="content-folder" autoCapitalize="none" autoCorrect={false} autoComplete="off" placeholder="e.g. inputs" value={folder} onChangeText={setFolder} />
      </>}
      {files === null ? (err ? <P size={2} color="red" mt={3}>{err}</P> : <Flex gap={2} align="center" mt={3}><Spinner /><Muted>Loading files…</Muted></Flex>)
        : !files.length ? <P size={3} color="gray" align="center" mt={8} mb={8}>No files.</P>
        : <Card mt={3} data={{ "content-files": name }}>
          {files.map((f) => (
            <Flex key={f.path} align="center" gap={2} pt={1} data={{ "content-file": f.path }}>
              <Text size={2} style={{ flex: 1, minWidth: 0 }} lines={1}>{f.path}</Text>
              <Muted>{fmtBytes(f.size)}</Muted>
              {Platform.OS === "web" && <Button size={1} variant="soft" color="gray" onPress={() => downloadContent(name, f.path).catch((e) => failed(e))}>Download</Button>}
              <Button size={1} variant="soft" color="red" onPress={() => del(f)}>Delete</Button>
            </Flex>
          ))}
        </Card>}
      <Rows mt={3}><Row label="On the box">{"claude-records/.content/" + name + "/"}</Row></Rows>
      <Flex mt={4}><Button id="content-delete-store" variant="soft" color="red" onPress={delStore}>Delete store…</Button></Flex>
      <Heading size={2} mt={4} mb={1}>In a session</Heading>
      <Muted>~/content/{name}/ at every start; `content-sync push {name}` sends changes back.</Muted>
    </Page>
  );
}
