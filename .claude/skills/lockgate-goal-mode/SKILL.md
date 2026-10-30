---
name: lockgate-goal-mode
description: >-
  Drive a long-running goal ("Achieve RCE on this app") over the lockgate MCP
  plane: the four stop states, the attack-tree frontier, canary nonces as the
  success oracle, milestones against stalls, and dead-end discipline across
  context relaunches. Use when a lockgate MCP server is available and the task
  is a goal to pursue to settlement, not a question to answer.
---

# lockgate-goal-mode

You are running toward a **goal**, and the run only ends one of four ways.
That constraint is code, not discipline: `settle_goal` refuses everything
else, and refuses `achieved` without a canary hit. Work *with* that machinery
— it is what makes the run's story auditable.

## Opening the run

1. `open_goal` — the goal text, and a **success predicate you can defend in
   prose**: for RCE-shaped goals, "command output observable via a canary
   callback carrying our nonce". Name the operator's canary domain.
2. Seed the frontier with `propose_frontier_item`, broadly — every ladder
   that could plausibly reach the goal:
   `auth_bypass`, `upload_traversal`, `deserialization`, `ssti`,
   `cmd_injection`, `ssrf_internal`, `known_cve`, `tenant_admin`,
   `signup_mass_assignment`, `config_exposure`. Priorities are yours;
   dead-ends you bury later are also results.
3. `record_milestone` for the rungs as you pass them ("anonymous surface
   mapped", "T1 session manufactured").

## The loop

1. **Read state first**: `get_goal` (it carries the state digest) — every
   context, every time. The digest names the active frontier, the milestones,
   and the **dead ends you must not retry** without new information.
2. **Pick the highest-priority `proposed` item**, mark it `active`, expand it
   with the recon skill's machinery: leads (`create_lead`), tagged sends
   (`lead:<id>` tags), controls, `adjudicate_lead`.
3. **One canary per attempt**: `mint_canary` before anything that could
   fire back OOB, and embed `<nonce>.<canary_domain>` (DNS-style — in SSRF
   targets, file paths, command strings) or `?c=<nonce>` (URL-style). When
   the listener reports a callback, `record_canary_hit` with the flow id of
   the payload send. The nonce names the *exact attempt* that fired.
4. **Grade honestly**: item worked partway → `milestone_reached` + a
   `record_milestone`; item does not work → `dead_end` **with the reason**
   (the tool refuses to bury without one — that note is what a relaunched
   context reads instead of repeating you); budget ran out mid-item →
   `exhausted`.
5. **Rotate on stall**, hammer on nothing. A rate-limit refusal names its
   `retry_after` — respect it and expand a different item. A Cloudflare wall
   is milestone zero of whatever it blocks: escalate the egress ladder
   (trusted residential exit, real browser once, `cf_clearance` replay pinned
   to the same exit), and if it holds, bury the item with the wall named.
6. **Identities** come from the registration skill; sends carrying them use
   `as_identity`. The engine refuses identity-bearing sends on non-trusted
   egress — that refusal is a floor, never an obstacle to route around.

## The four exits

`settle_goal` accepts exactly one of these, each with a written reason:

- `achieved` — **only with a recorded canary hit.** If you believe you
  succeeded but no nonce fired, you are not done: find why the callback
  cannot return (egress, DNS, egress-locked environments) or keep working.
  Settle the lead with a control and adjudicate it first; the finding is the
  deliverable, the goal state is the bookkeeping.
- `budget_exhausted` — the wall-clock or spend budget is gone. Say what was
  in flight and what the next context should pick up.
- `frontier_empty` — every item is `dead_end` or `milestone_reached` with
  nowhere further. The reason lists the ladders tried and the walls found —
  this is a real result, not a failure state.
- `operator_killed` — the operator's kill; write what they will want to know.

There is no "I think I'm done". If the oracle has not fired, the goal is
still running.

## Relaunches

Contexts die; the run does not. On any fresh context: `run_state_digest`,
resume the active frontier item, and honor the dead-end ledger. Milestones
are the anti-thrash trail — no milestone across a long stretch of work means
you are circling, not progressing; change strategy or bury the item.

## Honesty

- Every finding goes through the leads pipeline (control, adjudication) —
  the goal plane never replaces verification, it sits above it.
- Report what was *not* reached and why. A buried ladder with its reason is
  coverage data; silence is a hole.
- The transcript never carries a credential: cookie values, app passwords,
  and registration passwords are structurally absent from every read path.
  Keep it that way in your own notes too — name identities and lengths, not
  values.
