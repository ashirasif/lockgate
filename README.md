# proxy

An intercepting HTTP proxy for security testing, in the shape of Burp or Caido
but driven from a terminal — and with an MCP server on the side so an agent can
work the same capture, queue and scope you are looking at.

Two frontends over one engine:

- a **ratatui TUI** with vim editing, for the human
- an **MCP server** with 27 tools, for an agent

Both hold the same `Arc<Engine>` in one process, so there is one SQLite writer
and neither can see stale state.

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
| **MCP** | 27 tools: recon, intercept, scope, send, format. Resources for full bodies |
| **Findings** | File a flow as a finding, triage severity and status by keystroke, delete. Also over MCP |
| **WebSockets** | A window of their own (W), separate from the HTTP history, with the handshake and a live frame transcript per connection. Correlated to the upgrade, also over MCP. Observed, not intercepted |
| **Compressed bodies** | gzip, deflate and brotli decoded for display and over MCP, re-encoded when an intercepted body is edited. Stored bytes are always what arrived |

### Partial

| Area | What is missing |
|---|---|
| **Findings** | Prose fields (description, repro, impact) are set over MCP only; the TUI files and triages but does not edit them |
| **Projects** | A startup picker opens, creates or forgets projects — one fuzzy search bar, top matches in a dropdown, Enter on a new name creates it, `Ctrl-d` forgets one (keeping its traffic on disk). `--project <name>` still skips straight in. What is missing is switching *inside* a running session: changing project means relaunching |
| **Notes** | `note` table exists, nothing reads or writes it |
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
  -out crates/proxy-core/src/ca/ca.key

openssl req -x509 -new -nodes \
  -key crates/proxy-core/src/ca/ca.key \
  -sha256 -days 3650 \
  -subj "/CN=proxy local CA" \
  -out crates/proxy-core/src/ca/ca.cer
```

### 2. Trust it on the device under test

Nothing HTTPS works until the CA is trusted. `crates/proxy-core/src/ca/ca.cer`
is the file to install.

Or, once the proxy is running, browse to **http://proxy/** through it — that is
the only practical route onto a phone. `--export-ca <path>` writes the same file.

- **macOS** — `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain crates/proxy-core/src/ca/ca.cer`
- **Firefox** — has its own store: Settings → Privacy & Security → Certificates → Import
- **iOS/Android** — transfer the `.cer`, install it, then enable it for full trust in the OS certificate settings

Treat the key as sensitive: anything trusting this CA can be intercepted by
whoever holds it.

### 3. Run

```sh
cargo run --release                          # proxy 3000, MCP 3001, project "default"
cargo run --release -- --project acme -p 8080
cargo run --release -- --help
```

Point a browser or `curl -x http://127.0.0.1:3000` at it. Project data lives in
`~/.proxy`; naming a project both creates and reopens it.

`--mcp-port 0` turns the MCP server off, which is what lets a second instance
run quietly alongside the first.

---

## Keys

`?` is not a help key; `:help` prints the summary and `<C-k>` opens the command
palette. Windows are `P` proxy, `W` websocket, `I` intercept, `R` repeater,
`C` scope, `T` findings, `S` sitemap, `A` automate — `gt`/`gT` cycle.

| | |
|---|---|
| **Everywhere** | `<Space>r` resend · `<Space>s` send to Repeater · `<Space>i` toggle hold · `<Space>c` bypass scope · `:q` quit |
| **WebSocket** | `j`/`k` move between connections · the selected one's handshake and frames show below |
| **Intercept** | `f` forward · `d` drop · `F`/`D` all · `<C-w>` switch pane · `<CR>` open preview |
| **Repeater** | `n` new tab · `x` close · `gs` / `{count}gs` switch · `[` `]` history · `p` raw/pretty |
| **Scope** | `n` new · `a` include · `x` exclude · `d` delete · `<CR>` activate or toggle · `<C-w>` switch pane |
| **Sitemap** | `<CR>` fold · `a` scope host · `d` unscope host |
| **Findings** | `s` severity · `c` status · `d` delete · `<Space>f` file the selected flow |
| **In a buffer** | vim motions and operators · `gq` format body · `<C-g>` hand to `$EDITOR` · `<Esc>` leave |

Digits are vim counts, never window bindings — which is why tab selection is
`{count}gs` rather than `1`-`9`.

---

## Architecture

```
proxy-core   engine, capture, storage, scope, intercept, wire-text codec
proxy-mcp    MCP server (HTTP, not stdio — the TUI owns this process's stdio)
proxy-cli    the TUI, and the binary that wires all three together
```

`proxy-core` knows nothing about presentation; the frontends depend on it and
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
cargo test --workspace      # 398 tests
cargo clippy --workspace --all-targets
cargo fmt --all
```

Tests are the documentation of intent here — most assert *why* something
behaves as it does, not just that it does.
