# core/kernel: the kernel of the target design

The kernel parts of docs/DESIGN.md "Target design: succession certs, grants and the kernel" (DECISIONS 163), each its
own package, HTTP handler and binary, each holding only its own private key. The old core (`core/*.go`) is untouched
and still builds the live core image; nothing here is deployed yet (no manifest, no image).

| package | binary | part | holds |
|---|---|---|---|
| `kernel` | | shared: sets, pairs, envelope, hash-to-curve keys, document formats, HTTP helper | nothing |
| `kernel/notary` | `cmd/notary` | log notary | its key, the log head |
| `kernel/notarizer` | `cmd/notarizer` | succession notarizer (the table, as data) | its key, the sources already continued |
| `kernel/mover` | `cmd/mover` | grant mover | its key |
| `kernel/merger` | `cmd/merger` | grant merger | its key |
| `kernel/identitysigner` | `cmd/identity-signer` | identity signer | its key |
| `kernel/gullible` | `cmd/gullible-signer` | gullible signer | its key |
| `kernel/spawner` | `cmd/spawner` | spawner | its key, the Fly token |
| `kernel/secrets` | `cmd/secrets` | secrets | its key, the stores, the unlocks |
| `kernel/ktest` | | test helpers (fresh keys for every role, documents signed directly) | |

Every binary reads `KEY_FILE` (its PKCS#8 P-256 key), `ADDR` (default `:8090`), optionally `BOX_KEY_FILE` (the box key
signs `jarvis2-<role>-identity <signingKey> <agreementKey>`), and, when it checks other parts' signatures,
`ROSTER_FILE`: a JSON object of public keys `{notary, notarizer, mover, merger, spawner, identity, gullible, secrets,
phone, root}`. Extra: notary `LOG_FILE`, notarizer `STATE_FILE`, spawner `MACHINE_URL`. `-tags fakefly` gives the spawner
an in-memory Fly and secrets an in-memory GitHub (CI only). Each answers `GET /identity` → `{role, signingKey,
agreementKey?, boxSig?}`; errors leave signed by the part (`{"kind":"error","error":…}`) with an HTTP status.

## Formats

Keys and points: base64 of the 65-byte uncompressed P-256 point. A document is `{"payload": "<exact JSON>", "sig":
"<base64 DER ECDSA-SHA256 over payload>"}`; its ID is hex sha256 of the payload. Payloads are decoded strictly: an
unknown field refuses the document. Golden vectors in `testdata/` (keys derived from a public seed, `keys.json`).

- **Set** (finite or cofinite, exact strings, sorted by byte order, each once, 1–1024 bytes of UTF-8):
  `{"only":["shell","store:claude"]}` or `{"except":["shell"]}`; everything = `{"except":[]}`.
- **Conditions**: a sorted JSON array of strings, each once. **Pair** = `{allowed: Set, conditions}`; ≤ is allowed ⊆
  and conditions ⊇; meet = (∩, ∪); ⊤ = `({"except":[]}, [])`.
- **Object**: `{"id":"sink"}` | `{"id":"source-<32 hex>","image","settings","snapshot"}` (each optional) | `{"id":"<fly
  id>","signingKey","encryptionKey"}`. Compared whole. A source's and the sink's keys are hashed from
  `"jarvis2 sink signing"`, `"jarvis2 sink encryption"`, `"jarvis2 source-<id> signing"`, `"jarvis2 source-<id>
  encryption"` (try-and-increment, `h2c.go`; `testdata/h2c.py` recomputes them).
- **Succession cert** (signed by the key of `signer`): `{"kind":"succession","signer":"phone|root|spawner|identity|gullible",
  "predecessor":Object,"successor":Object,"allowed":Set,"conditions":[…]}`.
- **Challenge** (notary): `{"kind":"challenge","seq","prev","at","subject","about","nonce"}`; a cert's challenge has
  `subject` = the cert's ID and `about` = `"succession"`.
- **Notarization** (notarizer): `{"kind":"notarization","cert":<cert ID>,"challenge":<challenge ID>}`.
  **Notarized cert** = `{"cert","challenge","notarization"}` (three documents).
- **Grant** (mover, merger; ⊤ on the sink by root): `{"kind":"grant","by":"mover|merger|root","machine":Object,
  "allowed":Set,"conditions":[…],"from":[IDs]}`; mover `from` = [grant ID, notarization ID], merger = [a ID, b ID],
  root = [].

## Endpoints (all POST with a JSON body unless marked)

- notary: `/challenge {subject, about}` → challenge.
- notarizer: `/notarize {cert, challenge}` → notarized cert; `GET /table`.
- mover: `/move {grant, cert: notarized}` → grant (successor, G ⊓ P).
- merger: `/merge {a, b}` → grant (M, allowed₁ ∪ allowed₂, conditions).
- identity signer: `/sign {machine, allowed, conditions}` → cert (M, M, P).
- gullible signer: `/sign {predecessor, successor, allowed, conditions}` → cert.
- spawner: `/fly-token {sealed}` (`{"FLY_API_TOKEN"}` sealed to its agreement key, info `jarvis2/fly-token`);
  `/spawn {cert: notarized, ending in a source, region, size}` → `{"kind":"created","machine","source"}`;
  `/init {machine}` → cert (source, M, ⊤), 409 while it boots; `/kill {cert: M's notarized spawn cert, snapshot?:
  {sha256, sig}}` → cert (M, source-y, ⊤), 409 until Fly confirms it destroyed.
- secrets: `/state`, `/claim`, `/wipe`, `/store-key`, `/stores`, `/stores/create`, `/stores/mark-sensitive`,
  `/stores/write-key` (with `live`: the value sealed to secrets' agreement key, info `jarvis2/live-key\n<store>\n<key>`;
  writer `setup` + sig | `router` | `machine` + id), `/stores/versions`, `/stores/restore/{begin,finish,commit}`,
  `/unlock/begin {store}`, `/unlock/finish`, `/lock {id}`, `/unlocked`, `/deploy-keys/{begin,finish}`,
  `/pull {grant}` → `{"kind":"secrets","grant","machine","conditions","stores","versions","locked","missing","withheld",
  "sealed"}`, sealed (info `jarvis2/secrets`) to the grant object's encryption key: `{store: {key: value}}`.

## The table (`notarizer.Table`)

| shape | signer | condition |
|---|---|---|
| (sink, source) | phone | |
| (source, machine) | spawner | first successor |
| (source, machine) | phone | first successor |
| (machine M, M) | identity | same object |
| (machine, source) | spawner | |
| (source, sink) | gullible | |
| (any, any) | root | |

"First successor": the source has no earlier notarized successor through any row (kept in `STATE_FILE`).
