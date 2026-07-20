# proxy

An intercepting HTTP proxy for security testing, in the shape of Burp or Caido
but driven from a terminal — and with an MCP server on the side so an agent can
work the same capture, queue and scope you are looking at.

Two frontends over one engine:

- a **ratatui TUI** with vim editing, for the human
- an **MCP server** with 26 tools, for an agent

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
| **MCP** | 26 tools: recon, intercept, scope, send, format. Resources for full bodies |
| **Findings** | Schema, core API and MCP tools — see gaps for the missing half |

### Partial

| Area | What is missing |
|---|---|
| **Findings** | No TUI at all. Creatable and listable over MCP only, so a human cannot triage without an agent |
| **Projects** | The registry supports many; `main.rs` always opens `default`. No picker, no CLI flag |
| **Notes** | `note` table exists, nothing reads or writes it |
| **Repeater** | Tabs and history are in memory. Closing the TUI loses them |
| **Search** | `/` moves the cursor through the flow list. No body search, and no search tool over MCP |

### Not built

| Area | |
|---|---|
| **Compressed bodies** | Stored exactly as they arrived, so a `content-encoding: gzip` response renders as binary noise and no highlighting engages. Verified, not assumed — see [Decoding](#decoding-compressed-bodies) |
| **WebSockets** | Frames pass through untouched. The `ws_message` table exists and is never written |
| **HTTP/2** | Not enabled |
| **Match & replace** | Absent |
| **Automate / Intruder** | The tab is a stub that says so |
| **Structured filters** | No query language, no saved filters |
| **Retention** | Nothing evicts old bodies; a long engagement grows without bound |
| **CLI arguments** | None. Ports are hardcoded (proxy `3000`, MCP `3001`) |

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

- **macOS** — `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain crates/proxy-core/src/ca/ca.cer`
- **Firefox** — has its own store: Settings → Privacy & Security → Certificates → Import
- **iOS/Android** — transfer the `.cer`, install it, then enable it for full trust in the OS certificate settings

Treat the key as sensitive: anything trusting this CA can be intercepted by
whoever holds it.

### 3. Run

```sh
cargo run --release
```

- proxy listens on `127.0.0.1:3000`
- MCP listens on `127.0.0.1:3001`
- project data lives in `~/.proxy`

Point a browser or `curl -x http://127.0.0.1:3000` at it.

---

## Keys

`?` is not a help key; `:help` prints the summary and `<C-k>` opens the command
palette. Windows are `P` proxy, `I` intercept, `R` repeater, `C` scope,
`S` sitemap, `A` automate — `gt`/`gT` cycle.

| | |
|---|---|
| **Everywhere** | `<Space>r` resend · `<Space>s` send to Repeater · `<Space>i` toggle hold · `<Space>c` bypass scope · `:q` quit |
| **Intercept** | `f` forward · `d` drop · `F`/`D` all · `<C-w>` switch pane · `<CR>` open preview |
| **Repeater** | `n` new tab · `x` close · `gs` / `{count}gs` switch · `[` `]` history · `p` raw/pretty |
| **Scope** | `n` new · `a` include · `x` exclude · `d` delete · `<CR>` activate or toggle · `<C-w>` switch pane |
| **Sitemap** | `<CR>` fold · `a` scope host · `d` unscope host |
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

The next thing to build, and the decisions already taken:

1. **Store the wire bytes unchanged.** A proxy that silently rewrites what
   arrived is lying about what happened, and it makes `Content-Length` a
   fiction.
2. **Decode at the display and MCP boundary only.** `content-encoding` survives
   capture, so what a body is can always be recovered.
3. **Re-encode on forward** when an intercepted body was edited. Sending
   plaintext under a `gzip` header would break the client.

Verified rather than assumed: a 7.7KB JSON response arrives as 561 gzip-framed
bytes, is stored that way, and is unreadable in the preview.

---

## Known hazards

- **Regex host rules in scope are unanchored.** `example\.com` also matches
  `evil-example.com.attacker.net`. Glob is the default for this reason; the fix
  is to anchor them and has not been made yet.
- **A project database holds live credentials** in captured bodies. Treat the
  whole directory as sensitive rather than assuming any field is protected.

---

## Development

```sh
cargo test --workspace      # 355 tests
cargo clippy --workspace --all-targets
cargo fmt --all
```

Tests are the documentation of intent here — most assert *why* something
behaves as it does, not just that it does.
