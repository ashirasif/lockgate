# lockgate

![lockgate — browsing a capture, replaying a request, filing a finding](docs/demo.gif)

An intercepting HTTP proxy for security testing, in the shape of Burp or Caido
but driven from a terminal — and with an MCP server on the side so an agent can
work the same capture, queue and scope you are looking at.

Two frontends over one engine:

- a **ratatui TUI** with vim editing, for the human
- an **MCP server** with 53 tools, for an agent

Both hold the same `Arc<Engine>` in one process, so there is one SQLite writer
and neither can see stale state.


Reading the history, folding the sitemap, sending a `401` to the Repeater and
replaying it with a token attached, then filing the result as a finding — all of
it from the keyboard.

---

## Status

Honest summary. "Works" means used and tested; "partial" means the machinery
exists but you will notice what is missing.

### Works

| Area | |
|---|---|
| **Capture** | HTTP/1.1 through a MITM CA, flows and bodies persisted to SQLite. Bodies are content-addressed and deduped; anything over 5MB spills to `blobs/` |
| **Proxy view** | History newest-first, status/method/size/time columns, comments and highlights, marks and jumps, `/` search |
| **Intercept** | Both legs held independently, edit as raw wire text, forward/drop individually or all. Fails open — a frontend bug cannot wedge your browser |
| **Repeater** | Session tabs, per-session send history, response size and elapsed time, raw/pretty view toggle |
| **Sitemap** | Materialised host → path tree, folding, add/remove host to scope |
| **Scope** | Named scopes, include/exclude rules where excludes always win, glob/regex/CIDR host matching, filtering across Proxy and Sitemap, bypass toggle |
| **Editing** | A real vim grammar — counts, operators, text objects, visual mode, undo/redo, registers — plus `$EDITOR` handoff for anything it does not cover |
| **Display** | HTTP syntax highlighting, syntect for bodies (JSON, HTML, XML, GraphQL, protobuf, JS-in-`<script>`, …), JSON/HTML pretty-printing, OSC 52 clipboard |
| **MCP** | 53 tools — recon, intercept, scope, send, format, findings, notes, identities, policy, leads, materialise, report, scan, plus `list_targets`/`set_target` when one server runs several targets. Resources for full bodies |
| **Findings** | File a flow as a finding, triage severity and status by keystroke, retitle, delete. The write-up is edited in place with the same vim buffer the Repeater uses, `^g` to hand it to `$EDITOR` — one markdown document whose `## Reproduction` / `## Impact` / `## Remediation` sections are the prose columns a report is generated from. Saved on the way out. Also over MCP |
| **Notes** | Project markdown documents in a window of their own (K), edited in place with the same vim buffer the Repeater uses, `^g` to hand one to `$EDITOR`. Saved on the way out — there is no `:w`. Full CRUD over MCP, so an agent's working notes and yours are the same list |
| **WebSockets** | A window of their own (W), separate from the HTTP history, with the handshake and a live frame transcript per connection. Correlated to the upgrade, also over MCP. Observed, not intercepted |
| **Compressed bodies** | gzip, deflate and brotli decoded for display and over MCP, re-encoded when an intercepted body is edited. Stored bytes are always what arrived |
| **Identities** | Named session jars (adopted from a captured login, or built by hand) a replay can be sent *as* — `as_identity` on both send tools. Cookie values never leave the engine |
| **Policy** | Per-host send-rate ceiling and forbidden-URL rules, enforced in the engine's send path. Drawn over MCP; the floor under an agent's free hand |
| **Send tags** | A send can carry what it was *for* (`lead:idor-3`); `list_flows` filters on it, so evidence groups by the question that produced it |
| **Leads** | The ledger between recon and verification: propose, settle with a control, adjudicate. Each actor has its own write path, and a verdict without its control is refused in code |
| **Materialise** | The capture written out as a deterministic JSONL index (`endpoints`, `write-endpoints`, sitemap, findings, leads) for an agent to `rg`/`jq` |
| **Report** | The whole engagement — findings by severity with evidence, then the leads ledger — as one markdown document, on demand |
| **Passive scanner** | Header-level rules (CORS wildcard+credentials, cookie flags, HSTS/CSP absence, version banners) filed as `workflow`-origin drafts, deduped per rule+host, at capture and on demand |

### Partial

| Area | What is missing |
|---|---|
| **Findings** | CVSS and CWE are set over MCP only — the TUI shows a CWE but has no key to change one. Evidence links are fixed at filing on both sides |
| **Projects** | A startup picker opens, creates or forgets projects — one fuzzy search bar, top matches in a dropdown, Enter on a new name creates it, `Ctrl-d` forgets one (keeping its traffic on disk). `--project <name>` still skips straight in. What is missing is switching *inside* a running session: changing project means relaunching |
| **Repeater** | Tabs and history are in memory. Closing the TUI loses them |
| **Search** | `/` moves the cursor through the flow list. No body search, and no search tool over MCP |

### Not built

| Area | |
|---|---|
| **zstd bodies** | `zstd` is not decoded. Still rare in browser traffic, and the usable crate pulls a C library. Such bodies render as they arrived |
| **WebSocket interception** | Frames are recorded, never held. Pausing one side of a live full-duplex conversation reorders it against the other |
| **HTTP/2** | Not enabled |
| **Match & replace** | Absent |
| **Automate / Intruder** | The tab is a stub that says so |
| **Structured filters** | No query language, no saved filters |
| **Retention** | Nothing evicts old bodies; a long engagement grows without bound |

---

## Getting started

### 1. Generate a CA

The CA is embedded at compile time and `ca.key` is gitignored, so a fresh clone
will not build until you make your own. That is deliberate — a CA private key is
a per-machine secret, and one shared in a repository would let anyone who cloned
it intercept your traffic.

```sh
# EC P-256 in PKCS#8 — the form rcgen expects. RSA parses but is not what this
# is built against, so stick to this unless you have a reason not to.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out crates/lockgate-core/src/ca/ca.key

openssl req -x509 -new -nodes \
  -key crates/lockgate-core/src/ca/ca.key \
  -sha256 -days 3650 \
  -subj "/CN=lockgate local CA" \
  -out crates/lockgate-core/src/ca/ca.cer
```

### 2. Trust it on the device under test

Nothing HTTPS works until the CA is trusted. `crates/lockgate-core/src/ca/ca.cer`
is the file to install.

Or, once the proxy is running, browse to **http://lockgate/** through it — that is
the only practical route onto a phone. `--export-ca <path>` writes the same file.

- **macOS** — `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain crates/lockgate-core/src/ca/ca.cer`
- **Firefox** — has its own store: Settings → Privacy & Security → Certificates → Import
- **iOS/Android** — transfer the `.cer`, install it, then enable it for full trust in the OS certificate settings

Treat the key as sensitive: anything trusting this CA can be intercepted by
whoever holds it.

### 3. Run

```sh
cargo run --release                            # startup picker, then proxy 3000, MCP 3001
cargo run --release -- --project acme -p 8080  # skip the picker, open "acme" directly
cargo run --release -- --help
```

With no `--project`, a **startup screen** opens first: one search bar that
fuzzy-finds your projects, shows the top matches, and creates a new one when you
type a name it does not recognise (`Ctrl-d` forgets the selected project, leaving
its traffic on disk). `--project <name>` bypasses the picker — the scriptable path,
and what non-interactive runs want so they land on a known project without a menu
waiting on input.

Point a browser or `curl -x http://127.0.0.1:3000` at it. Project data lives in
`~/.lockgate`; naming a project both creates and reopens it.

Either front-end can run on its own:

```sh
cargo run --release -- --no-tui --project acme   # headless: proxy + MCP, driven by an agent
cargo run --release -- --no-mcp --project acme   # interactive: TUI + proxy, no MCP server
```

**Several targets in one server**: `--targets acme,acme-eu` runs one lockgate
process with a proxy per target (base port + 2 per target: `acme` on 3000,
`acme-eu` on 3002), one shared MCP, and a `/status` dashboard with a sidebar
naming every target. Each target keeps its own project database, scope, policy
and identities — nothing leaks across. The MCP session picks its target with
`set_target` (per session, so two agents can work two targets at once), and any
action tool takes an explicit `target:` argument that wins over the session
selection; the result echoes the target hit. Multi-target implies `--no-tui`
(the dashboard is the multi-target view).

`--no-tui` needs `--project` (or `--targets`) — the startup picker is itself a TUI. `--mcp-port 0`
turns the MCP server off too (same effect as `--no-mcp`), which is what lets a
second instance run quietly alongside the first.


### 4. Drive it from an agent

The MCP server is streamable HTTP at **`http://127.0.0.1:3001/mcp`**. Register it
with an agent — for Claude Code:

```sh
claude mcp add --transport http lockgate http://127.0.0.1:3001/mcp
```

and the agent gets the same 53 tools: survey flows, read full bodies as `flow://`
resources, walk the sitemap and WebSocket frames, replay through scope, file
findings, and keep notes alongside yours. A bundled skill at
`.claude/skills/lockgate-recon` teaches the recon loop and the conventions that are judgement rather than mechanics — redact captured
secrets by default, rate severity against the threat model, set scope before a
replay.

### 5. Watch it from your phone

An autonomous run should not need you at the keyboard. Two channels:

- **`/status`** on the MCP port (`http://127.0.0.1:3001/status`) — the
  engagement at a glance, phone-shaped, refreshing every few seconds: the leads
  ledger, findings by severity, the agent's tagged sends, and its notes (which
  is where its reasoning lives — notes are the one document agent and operator
  share). `/status/report` renders the full markdown report. Read-only, and
  token-gated when you start with `--status-token <T>`. Loopback-bound by
  default; expose it only over something that authenticates you (Tailscale, an
  SSH tunnel), then add the token for defense in depth.
- **`--ntfy <URL>`** pushes the headline events — a finding filed, a lead
  settled — to any ntfy-compatible topic, so the phone buzzes when the run's
  story moves rather than when you remember to look.

---

## Keys

`?` is not a help key; `:help` prints the summary and `<C-k>` opens the command
palette. Windows are `P` proxy, `W` websocket, `I` intercept, `R` repeater,
`C` scope, `T` findings, `K` notes, `S` sitemap, `A` automate — `gt`/`gT` cycle.

| | |
|---|---|
| **Everywhere** | `<Space>r` resend · `<Space>s` send to Repeater · `<Space>i` toggle hold · `<Space>c` bypass scope · `<Space>f` file a finding · `<Space>n` start a note · `:q` quit |
| **Histories** | `d` hide the row from view (`V` first for a range) · `:unhide` bring everything back — nothing is deleted |
| **WebSocket** | `j`/`k` move between connections · `d` hide the connection · the selected one's handshake and frames show below |
| **Intercept** | `f` forward · `d` drop · `F`/`D` all · `<C-w>` switch pane · `<CR>` open preview |
| **Repeater** | `n` new tab · `x` close · `gs` / `{count}gs` switch · `[` `]` history · `p` raw/pretty |
| **Scope** | `n` new · `a` include · `x` exclude · `d` delete · `<CR>` activate or toggle · `<C-w>` switch pane |
| **Sitemap** | `<CR>` fold · `a` scope host · `d` unscope host |
| **Findings** | `<CR>` edit the write-up · `s` severity · `c` status · `r` retitle · `d` delete · `<Space>f` file the selected flow |
| **Notes** | `<CR>` edit the body · `n` new · `r` retitle · `d` delete · `<Space>n` start one from anywhere |
| **In a buffer** | vim motions and operators · `gq` format body · `<C-g>` hand to `$EDITOR` · `<Esc>` leave |

Digits are vim counts, never window bindings — which is why tab selection is
`{count}gs` rather than `1`-`9`.

---

## Architecture

```
lockgate-core   engine, capture, storage, scope, intercept, wire-text codec
lockgate-mcp    MCP server (HTTP, not stdio — the TUI owns this process's stdio)
lockgate-cli    the TUI, and the binary that wires all three together
```

`lockgate-core` knows nothing about presentation; the frontends depend on it and
never the other way around. Anything both frontends need lives there — which is
why `http_text` (messages as editable wire text) and `pretty` moved down into it
rather than staying in the TUI.

A few decisions worth knowing before changing things:

- **Scope is a view filter, never stored on a flow.** It is mutable, so a column
  would mean rewriting millions of rows on every rule edit.
- **Every row in `flow` really happened.** Repeater drafts are not flows.
- **Intercept fails open.** A closed channel, a cleared queue, a disabled leg or
  a process exit all release traffic unmodified.
- **Bodies are stored as they arrived.** See below.

---

## Decoding compressed bodies

Captured bodies are stored **exactly as they arrived**, compressed and all. A
proxy that silently rewrites what came off the wire is lying about what
happened, and it would make the stored `Content-Length` a fiction.

Decoding happens at the two boundaries where a body is *shown* to someone:

- the preview panes and the Proxy detail view, which say `(decoded gzip for
  display)` so a length mismatch is never a mystery
- `get_flow` and the `flow://` resources over MCP, which report
  `content_encoding` and whether the bytes were `decoded`

A compressed stream can only be decoded whole, so a *windowed* body read comes
back raw with `decoded: false` — decoding a window would produce
plausible-looking garbage. Fetch the resource to get it decoded.

Going the other way, an intercepted body that was edited is **re-encoded on
forward** and `Content-Length` corrected, because plaintext under a `gzip`
header is rejected by the client.

Every failure degrades to the original bytes. A truncated, mislabelled or
oversized body still renders — as noise, but it renders: in a proxy the bytes
that arrived are the evidence. Decompression is capped at 64MB, since the far
side is not trusted and a few hundred bytes can claim gigabytes.

## Known hazards

- **Regex host rules in scope are unanchored.** `example\.com` also matches
  `evil-example.com.attacker.net`. Glob is the default for this reason; the fix
  is to anchor them and has not been made yet.
- **A project database holds live credentials** in captured bodies. Treat the
  whole directory as sensitive rather than assuming any field is protected.

---

## Development

```sh
cargo test --workspace      # 500+ tests
cargo clippy --workspace --all-targets
cargo fmt --all
```

Tests are the documentation of intent here — most assert *why* something
behaves as it does, not just that it does.

The README GIF is regenerated rather than re-performed —
`docs/demo/seed.sh` builds a throwaway capture against a local origin and
`docs/demo/record.sh` renders it with [vhs](https://github.com/charmbracelet/vhs).
See [docs/demo](docs/demo/README.md).

---

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, sell it; just keep the copyright
notice.
