---
name: lockgate-recon
description: >-
  Drive the intercepting proxy's MCP to work a capture: survey captured HTTP/WebSocket
  traffic, map the sitemap, analyze how a target authenticates, verify by replaying
  requests, and file findings. Use when a `lockgate` MCP server is available (tools like
  list_flows / get_flow / create_finding) and you are doing recon, traffic analysis,
  or web-app pentesting against captured flows.
---

# lockgate-recon

You are driving an **intercepting HTTP proxy** (Burp/Caido-shaped, terminal-native)
through its MCP server. It has already captured real traffic into a per-target
**project**; your job is to make sense of that capture and record what matters.

If the `lockgate` MCP tools are registered, call them directly. Everything below is
about *how to use them well* — the server's own tool descriptions cover mechanics.

## The loop

1. **Survey** — `list_flows` (newest-first, bounded). Get the lay of the land: which
   hosts, methods, status codes, MIME types.
2. **Map** — `get_sitemap` for the host→path tree. This is how you find the API
   surface (e.g. `/graphql`, `/sync/batch`) versus static assets.
3. **Analyze auth** — pick the API calls, `get_flow` them, read the request headers.
   Determine the auth mechanism (cookie? bearer? custom header? signed param?) and
   where the credential actually lives.
4. **Verify** — don't assert an exploit from headers alone. `resend_flow` to confirm
   a request replays, and strip headers one at a time to see what the server truly
   enforces (e.g. does it reject a foreign `Origin`, or trust the browser?).
5. **Report** — `create_finding` with evidence linked to the flows that prove it.

## Bodies are resources, not inline

`get_flow` returns headers plus a **bounded preview** of each body. For the full
request/response body, read the resource at **`flow://{id}/request`** or
**`flow://{id}/response`** (text when UTF-8, else base64). Never assume the preview
is the whole body — check `truncated`/`total_len` before reasoning about payloads.

## Tool surface (grouped)

- **Read/recon**: `list_flows`, `get_flow`, `get_sitemap`, `list_ws_messages`
  (WebSocket frames, correlated to the upgrade), `list_findings`, `get_finding`.
- **Scope**: `list_scopes`, `create_scope`, `set_active_scope`, `delete_scope`,
  `list_scope_rules`, `add_scope_rule`, `set_scope_rule_enabled`, `delete_scope_rule`,
  `check_scope`.
- **Replay/send**: `resend_flow` (**scope-gated** — see below), `send_request`.
- **Intercept** (hold/edit/forward live traffic): `intercept_status`, `intercept_get`,
  `intercept_queue`, `intercept_set`, `intercept_forward`, `intercept_drop`,
  `intercept_answer_all`.
- **Record**: `create_finding`, `update_finding` (revise one as you confirm it),
  `annotate_flow` (comment/highlight a flow).
- **Format**: `format_message` (pretty/raw a request or response).

## Rules

**Redact secrets by default.** When you surface captured credentials — cookies,
`Authorization`/token headers, API keys, signed params — show the **name and
byte-length only**, e.g. `session:…=<307b>`, `authorization: Bearer …<412 chars>`.
Reveal full secret values **only when the user explicitly asks**. This protects the
transcript, which may be shared.

**Be honest about severity.** `severity` is `info | low | medium | high | critical`.
Rate against the threat model, not the scariness of the words. Behavior that is
*expected* given the setup — e.g. a session cookie being visible because a trusted
MITM CA is installed — is **`info`**, however alarming the raw value looks. Reserve
`high`/`critical` for defects that are actually exploitable without already owning
the endpoint. Inflated severity is noise.

**Scope before replay.** `resend_flow` is gated on the active scope: if the target
host isn't in scope, the replay is refused (a guardrail against hitting out-of-scope
hosts). Set it up first — `create_scope`, `add_scope_rule` for the in-scope host(s),
`set_active_scope` — then replay. `check_scope` tells you whether a host would pass.

## Filing a finding

`create_finding` requires `title`, `severity`, `description_md`. Strongly prefer to
also set: `impact_md`, `repro_md`, `remediation_md`, `cwe`, and `evidence` — a list
of `{ flow_id, label }` pointing at the flows that demonstrate it. `status` defaults
to `draft`. Write the prose in Markdown; state the mechanism plainly and keep the
threat model explicit (what the attacker must already have).

A finding is not write-once. `update_finding` revises any of it — file at the
confidence you actually have, then triage the severity and status up as evidence
arrives, rather than sitting on a draft until it is perfect. Omitted fields are left
alone and a given markdown field replaces that whole section, so `get_finding` first
if you mean to append. Evidence links are fixed at filing.

A good finding reads: what the mechanism is → what an attacker with the stated
position can do → exact repro steps against a numbered evidence flow → whether it's
actually a defect or expected behavior being documented.

## Footguns

- **One proxy at a time.** It's a singleton on `127.0.0.1:3000` (capture) / `:3001`
  (MCP). Two instances can't both bind; the second silently captures nothing. Capture
  is persisted **per project**, so restarting loses no history.
- **WebSockets are observed, not intercepted.** You can read frames (`list_ws_messages`)
  but not hold/edit them mid-flight.
- **HTTP/2 isn't enabled**; some clients that speak it to the proxy show up as
  connection errors rather than flows.
