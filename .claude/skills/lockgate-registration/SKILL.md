---
name: lockgate-registration
description: >-
  Self-register accounts on the target so the run manufactures its own identity
  tiers — the black-box claim. Use when a lockgate MCP server is available and
  the run needs a session at a tier nobody handed you credentials for.
---

# lockgate-registration

The run needs a **role matrix** before access-control work means anything:
anonymous, self-registered user, and whatever elevated tiers the app gives
away. Nobody hands you those credentials — you make them. Every identity you
mint is labeled by where it came from, and that label is the audit trail the
report's black-box claim hangs off.

## The tier ladder

Work upward, and record each step as a milestone (`record_milestone`):

- **T0 anonymous** — free. Crawl and materialise before any account exists.
- **T1 self-registered** — open signup. This skill's main job.
- **T2+** — hunt the self-serve path in this order: "sign up with Google"
  (often an admin seat of a *new* tenant on multi-tenant SaaS — the target
  then shifts to cross-tenant access), mass-assignment on the signup request
  itself (replay the registration POST with `role`-shaped fields added — when
  it works, that is itself a finding), invite/referral codes (guessable,
  leaked in responses, accepted cross-tenant), upgrade-workflow logic flaws.
  A tier the app gates behind genuine human approval is a **documented
  coverage gap**, not a failure — say so in the report and move on.

## Registering (SSO first)

1. **Prefer "Sign up with Google"** over email+password: the OAuth redirect
   usually skips the captcha and the email-verification dance, and the
   fingerprint is maximally legitimate. The Google session lives in the
   browser profile the operator pre-provisioned — the agent *uses* Google
   accounts, it never creates them.
2. Email+password otherwise: generate a strong password and hand it to
   `create_identity`'s `password` — the engine holds it; it never appears in
   your context. Give the form a plus-alias of the registered mailbox
   (`probe+t1@gmail.com`).
3. Verification mail: `await_verification_mail` with the alias as `address`
   and the target's domain as `sender_contains`. You get the confirm link
   and/or code back. Bounded poll — a `timed_out: true` means re-submit the
   form or widen the filter, not loop forever.
4. Mint the identity: `create_identity` with
   `provenance: "self_registered"`, `seed_account` the alias used, the
   session cookies, and the `password`. Never claim `self_registered` for a
   credential the operator gave you — the report's honesty rides on that
   column.

## After registering: learn what you got

Crawl as the new identity, `materialise` to its own directory, and
`diff_tiers` against the previous tier's directory. Every `only_in_*` row is
an access-control question and a lead candidate (`create_lead`, kind `authz`).
The diff is the tier boundary made visible — this is the whole point of
manufacturing identities.

## Walls, and what they are

- **Captcha** — try a real browser via the persistent profile first; if the
  wall holds, record a milestone naming it (`captcha blocked signup on X`)
  and move on. Solver services are the operator's policy call, not yours to
  improvise mid-run.
- **SMS verification** — same treatment: milestone, move on. An
  operator-provided number pool, if one exists, is the operator's call.
- **Free-email rejection** (B2B apps wanting work addresses) — note it; the
  catch-all domain is the operator's later answer.

Walls are results. A signup flow nobody can automate is intelligence about
the target's exposure, and the report should carry it.

## Cleanup

`seed_account` is the registry: at run's end, every account created is
listed on its identities. The report's postmortem lists them for deletion.

## Rules

- One mailbox per Google account (`add_mailbox_account` once); await aliases
  with the `address` parameter — do not register one mailbox per plus-alias.
- A handful of accounts per tier. Registration is normal user behaviour at
  this scale; a hundred accounts is abuse and noise, and the rate ceiling
  will say so before your judgment does.
- The password field is write-only custody. You cannot read it back — if you
  need to re-login, that is the browser layer's job with the engine typing.
