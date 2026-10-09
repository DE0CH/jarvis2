// The end of a conversation that is not running — what you said and what Claude answered — so a session
// can be recognised before it is brought back: a paused session's, from its pause snapshot
// (api/sessions/:id/tail, action = Resume), or a destroyed one's, from its archive (api/records/:id/tail,
// action = Restore). Opens scrolled to the last message.
import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { api, type TailMessage } from "../lib/api";
import { Button, Card, Flex, Muted, P, Spinner, Text } from "../ui/kit";
import { Page, closePage } from "../ui/page";

export type TranscriptSpec = { title: string; note: string; path: string; action?: { label: string; run: () => void } };

export function Transcript({ spec }: { spec: TranscriptSpec }) {
  const [msgs, setMsgs] = useState<TailMessage[] | null>(null), [err, setErr] = useState("");
  const scroll = useRef<any>(null), atEnd = useRef(false);
  useEffect(() => {
    let live = true;
    api<{ messages: TailMessage[] }>("GET", spec.path).then((j) => { if (live) setMsgs(j.messages || []); }, (e) => { if (live) setErr(e.message); });
    return () => { live = false; };
  }, [spec.path]);
  const toEnd = () => { if (msgs && !atEnd.current) { atEnd.current = true; scroll.current?.scrollToEnd?.({ animated: false }); } };
  return (
    <Page title={spec.title} scrollRef={scroll} onContentSizeChange={toEnd} id="transcript"
      right={spec.action ? <Button id="pt-action" onPress={() => { closePage(); spec.action!.run(); }}>{spec.action.label}</Button> : undefined}>
      <Muted mt={2}>{spec.note} · the last messages of the conversation</Muted>
      {err ? <P size={2} color="red" mt={3} id="pt-error">{err}</P>
        : !msgs ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Reading the transcript…</P></Flex>
        : !msgs.length ? <P size={3} color="gray" align="center" mt={6}>No messages in the last part of the transcript.</P>
        : <View nativeID="pt-msgs" style={{ gap: 12, marginTop: 12 }}>
            {msgs.map((m, i) => (
              <View key={i} {...({ dataSet: { role: m.role } } as any)}>
                <P size={1} weight="bold" color="gray" upper mb={1}>{m.role === "user" ? "You" : "Claude"}{m.at ? <Text weight="regular">{" · " + new Date(m.at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</Text> : null}</P>
                {m.role === "user"
                  ? <Card size={1} variant="surface"><P size={2} selectable>{m.text}</P></Card>
                  : <P size={2} selectable>{m.text}</P>}
              </View>
            ))}
          </View>}
    </Page>
  );
}
