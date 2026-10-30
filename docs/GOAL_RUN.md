# The first goal run — a runbook (phase 11)

Everything phases 6–10 built is infrastructure for one shape of evening: you
write a goal on a target you own, walk away, and read the story from your
phone. This is how to spend that evening.

## Phase 0 — operator setup (before any code runs)

- [ ] **Google account pool** — 2–5 throwaway accounts, 2FA on, IMAP
  app-passwords generated. One persistent Chrome profile each. The agent
  *uses* these; it never creates Google accounts.
- [ ] **Canary domain** — any cheap domain with a wildcard DNS/HTTP listener
  you can watch (interactsh, or a tiny `A * → this-box` + tcpdump). Every
  `<nonce>.canary.example.net` lookup that arrives is an oracle hit waiting
  to be recorded.
- [ ] **Target** — an app you own, or a deliberately vulnerable one. Not a
  third party you have no paper for; the policy layer is the record, and the
  record should be true.
- [ ] **Watch channels** — `--ntfy <URL>` for headline pushes,
  `--status-token` on `/status` for the phone view.
- [ ] **VPS or laptop** — headless Chrome present (`browser_ensure` handles
  it), trusted egress known. Add the operator's residential exit as a
  `trusted` egress exit if you have one; leave the hostile pool empty for
  run #1.

## Launch

```sh
cargo run --release -- --no-tui --project goalrun-1 --ntfy <URL> --status-token <T>
```

Point the agent (Claude Code with the lockgate + goal-mode + registration
skills registered) at `http://127.0.0.1:3001/mcp` with the brief:

> Achieve RCE on <target>. The goal plane is yours: open the goal with a
> canary predicate, manufacture your identity tiers, and settle only through
> the oracle. Budget: N hours.

Then set scope yourself (`create_scope`, host rules) and draw policy (rate
ceiling, forbidden URLs) — or check what the agent drew before letting it
send anything. The guardrails are code; the *width* of the free hand is the
operator's one-time act.

## What to watch

- `/status` — leads ledger, findings by severity, the agent's tagged sends,
  its notes. The reasoning lives in the notes; that channel is shared.
- ntfy buzzes on findings and settled leads. A canary hit should buzz you
  and the agent at the same moment.
- The state digest (`run_state_digest` over MCP) is the run's self-image:
  active frontier, milestones, dead ends. Watch the milestone trail — a long
  gap with a busy transcript is a stall, and the right intervention is a
  steer ("bury it, next item"), not a kill.

## During the run

- **Do not hand over credentials.** The entire point. If a tier genuinely
  needs an operator assist, `adopt_flow_session` is the fallback and the
  identity is labeled `operator` — the report will say which findings rest
  on which provenance.
- **Kills are cheap**: the TUI's observation deck (run a second instance
  against the same project with `--mcp-port 0`) or just settling the goal
  `operator_killed` from a phone-typed MCP call.

## Postmortem (the ritual that makes run #2 better)

1. `generate_report` — findings with evidence, the leads ledger, and the
   provenance of every identity that demonstrated anything.
2. Read the goal's `stop_reason_md` and the frontier: which ladders were
   buried and why, which walls (captcha, SMS, Cloudflare) appeared, what the
   oracle said.
3. Cleanup: every `seed_account` on a `self_registered` identity is an
   account to delete; `list_identities` is the registry.
4. Fold back: missing ladder in the seeds? Playbook that kept failing?
   Milestone vocabulary that hid a stall? Fix it in the skills before run #2
   — the acceptance criterion for phase 11 is that the second run
   measurably outperforms the first.

## What "done" looks like

The goal settles through one of the four states with its reason written;
every finding in the report traces to adjudicated leads with control-backed
verdicts and flow-linked evidence; every identity that demonstrated anything
carries honest provenance; and the transcript — anywhere you look at it —
contains no credential values. That is the whole architecture in one
sentence, tested end to end.
