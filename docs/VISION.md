# LockGate Vision

Where this project is going: from an intercepting proxy with an MCP server to
**the best autonomous agent for pentesting and minor bug bounty** — with the
human out of the decision loop, never out of the picture.

Written 2026-10-30, after the identity-plane work landed. Statuses reflect the
tree at that commit.

---

## The shape of the thing

One rule did most of the architectural work once we saw it:

> **All agent HTTP goes through the lockgate proxy.**

Hector (~/work/hector) proved the brain: a crawl → materialise → recon →
verify → adjudicate loop where one capable agent with a shell beats any fixed
decomposition of vulnerability classes. Its weakness is evidence — its own docs
note the model proxy "sees requests but not which lead a request belonged to."

LockGate is the opposite half: every request through it is captured, persisted,
replayable, scope-gated, and watchable in the TUI — but it has no loop.

So: **hector goes into lockgate, not the other way around.** LockGate is the
body and the evidence plane; the orchestration loop is ported to drive it over
MCP. The brain stays an external agent (Claude Code or any LLM harness) —
model churn is not something to fuse into a Rust core. The in-process brain,
if it ever comes, is a later orchestration layer on top of primitives good
enough that a dumb agent succeeds.

One server, many targets — the operator's interface:

```
lockgate serve --targets acme,acme-eu
  ├─ proxy :3000 → acme      (own project DB, scope, policy, identities)
  ├─ proxy :3002 → acme-eu
  ├─ MCP :3001 (shared)      — list_targets / set_target (per agent session);
  │                            every action tool takes an explicit target that
  │                            wins, and echoes the target it hit
  └─ /status (shared)        — sidebar of every target, overview + drilldown
```

```
Program (e.g. a bug-bounty vendor)
  targets[] ── each: a lockgate project + scope + budget + policy
       │
  CRAWL (swarm-crawler, multi-target boards) ──► via lockgate proxy
       │
  MATERIALISE (filesystem read plane: endpoints, bundles, access matrix)
       │
  RECON (one agent, shell) ──► leads
       │
  VERIFY ×N (1 agent per lead: shell + browser + TOTP + mailbox,
             attacks via lockgate MCP send/resend — scope-gated, captured,
             tagged with the lead that fired them)
       │
  ADJUDICATE (read-only, epistemics) ──► create_finding(evidence: flow ids)
       │
  TUI = the operator's observation deck + one kill switch.
```

### What we port from hector, as-is

- The 5-node loop: crawl → materialise → recon → verify×N → adjudicate.
- **Reads are the filesystem; writes are validated tools.** Before recon runs,
  the crawl is materialised to a directory (endpoints, deduplicated bundles,
  access matrix, prior leads) and agents `rg`/`jq` over it.
- **I1/I2: the harness owns the records and the termination.** The LLM decides
  what to explore; it never keeps the crawl state or owns a `done()` tool.
- The destructive-action gate, and the adjudicator (the only thing that catches
  confident false positives — in hector it never once refuted a verdict; ours
  must actually be exercised).
- The tool set: ffuf, jwt tools, secrets scanner, rate limiting, target lock,
  TOTP, mailbox.
- LiteLLM-style routing/spend accounting on the model path.

### What we do NOT port

- The nine-worker class fan-out (single-agent redesign evidence: one agent with
  the same data found 3/3 top findings; the pipeline found 0/3).
- Process-global cookie jars as the HTTP layer. LockGate's engine replaces
  `tools/http.py` — with persistence, scope enforcement, and policy.

## Identity: the agent acts as the operator

The point is a **free hand**: the agent logs into third-party services through
the operator's accounts without waiting for permission or credentials mid-run.

- **Identity** = a named cookie jar + optional TOTP secret + host binding,
  stored in the project database next to the flows (migration v4).
- **Adopt-session**: the operator logs in through the proxy once by hand; one
  call (`adopt_flow_session`) turns a captured flow into a named identity. No
  password ever enters an LLM context.
- **`as_identity` on replay**: the identity's jar replaces the request's
  cookies wholesale — never a merge, so evidence always shows what that session
  would really send. Replay the same request under two identities and diff the
  answers: that is the access-control primitive.
- **Self-service refresh** (hector's hard-won lesson: sessions die *mid*-run):
  the agent gets a persistent-profile browser, a TOTP tool, and a mailbox tool,
  and re-login is an ordinary tool call. For Google SSO: the Google session
  lives in the browser profile, TOTP codes derive from the stored secret, email
  codes via IMAP — the agent authenticates *as a session of ours*.
- **Redaction is structural**: cookie values never leave the engine's core.
  Reads report names, domains, and lengths. A transcript cannot leak a live
  session by construction.

## Infra

- **VPS now, mac mini later.** A VPS runs Chrome/Chromium *headless* — that is
  all Playwright ever did. `browser_ensure` auto-detects: no display →
  `--headless=new`; `LOCKGATE_CDP_*` env overrides configure binary, port,
  profile, and headlessness for the server shape.
- **The mac mini is the endgame for identity-bound browsing**: real Apple TLS
  stack, residential IP, keychain for passkeys. Until then, keep authenticated
  work cookie-based (adopted sessions, no re-logins) on the VPS, and route
  sensitive logins through a residential exit.
- **Fingerprints are the real blocker, not the UA string.** macOS UA does not
  survive JA3/JA4 or datacenter-IP reputation.
- **Browser**: self-hosted Chrome with persistent profiles per identity for
  anything authenticated (sessions are too sensitive to scatter across a cloud
  browser); browserbase-style pools only for anonymous scale-out.
- **Web search**: one tool into recon (program policy, changelogs, known CVEs).
- **Observability from anywhere**: `/status` on the MCP port (leads, findings,
  tagged sends, the agent's notes) with `--status-token` when exposed, and
  `--ntfy` push on headline events. The human is out of decisions, never out
  of the picture — including from a phone.

## Safety: the free hand has a floor

Autonomy without a floor is automated trouble. The floor is **enforced in
code, not prompts** (hector's production-roadmap lesson D: prompts do not
establish controls).

- **Policy as data, per project** (migration v5): a per-host send-rate ceiling
  and forbidden-URL patterns — the out-of-bounds list every program publishes.
  Enforced in the engine's send path, so TUI, MCP, and agents are bound
  equally. Default is permissive: a hand-driven session notices nothing, and an
  agent's free hand is exactly as wide as the operator drew it.
- **Scope stays the hard boundary** — replays are refused outside the active
  scope; the crawler is scope-locked the same way.
- **Destructive-action classification** before dispatch (ported from the
  crawler gate): no state-mutating request in a fuzz job without it passing the
  gate.
- **Send tagging** (`flow.tag`): agent sends carry the lead/question that fired
  them (`lead:idor-3`), so evidence filters by the question that produced it —
  closing hector's attribution gap.
- **The TUI is the observation deck**: the human is out of decisions, never out
  of the picture, and the kill switch is one keystroke.
- **Program policy as data is also the ToS compliance record**: rate ceilings,
  forbidden techniques, out-of-bounds tests — written down where the enforcer
  reads it.

## Roadmap

| Phase | What | Status |
|---|---|---|
| 1 | Identity plane: identities, adopt-session, `as_identity`, TOTP/mailbox hooks, CDP Chrome ensured by lockgate | **done** |
| 2 | Guardrails: headless CDP for the VPS, policy (rate + forbidden URLs) enforced in the engine, send tagging | **done** |
| 3 | Program layer + port the loop: programs in the registry, materialise, leads ledger, recon → verify over lockgate MCP | **done** (lockgate side) |
| 4 | Adjudicate + report generation | **done** (lockgate side) |
| 5 | Passive scanner on capture | **done** |

Phases 3–4 live partly outside this repo (the orchestrator harness and its
prompts) but every capability they need — scope, identities, policy, tagging,
findings with evidence links — lands here first.

## Principles this must not betray

- **Every row in `flow` really happened.** Replays are recorded as what
  actually left, post-identity, post-policy.
- **The harness is the source of truth.** LLMs judge; they do not keep records
  or decide completion.
- **Guardrails are code.** A control that lives in a prompt is a wish.
- **Honest severity, honest coverage.** Report what was *not* reached and why;
  rate against the threat model, not the scariness of the words.
- **One process, one writer, two frontends** — the human's TUI and the agent's
  MCP stay the same `Arc<Engine>`, so neither ever sees stale state.
