//! The chain playbook: composition candidates, proposed the moment something
//! new lands next to something old.
//!
//! The premise is that severity lives in compositions, not parts: an XSS and a
//! JavaScript-readable session cookie are each an ordinary finding, and
//! together they are an account takeover. Held apart they get triaged as
//! medium and low and stay there, because nothing in the pipeline ever puts
//! them next to each other. This module is that moment.
//!
//! It follows the scanner's split of labour. The playbook is deterministic —
//! a small table of known-worthwhile pairs over a small primitive vocabulary,
//! classified from what the rows already carry (a CWE on a finding, a kind on
//! a lead) — and it only ever *proposes*. Candidates are filed as leads of
//! `kind: "chain"` in the ledger, where the existing discipline takes over: a
//! verifier settles a chain with a control that demonstrates the composition
//! end to end, an adjudicator rules on it, and a refuted chain dies like any
//! other refuted hypothesis. The playbook is a floor, not a ceiling — pairs it
//! cannot see are the agents' to propose by hand, exactly like findings the
//! scanner cannot raise.

use rusqlite::{Connection, OptionalExtension};

use crate::finding::{self, NewFinding};
use crate::lead::{self, Lead};

/// The CWEs that name a primitive. Only the playbook's own classes are here:
/// a CWE that composes with nothing is a label, not a link. The passive
/// scanner's rules already file these CWEs, so its drafts compose without any
/// special-casing — a missing-CSP draft is already a `no-csp` leg.
pub fn primitive_of_cwe(cwe: &str) -> Option<&'static str> {
    let digits: String = cwe.chars().filter(|c| c.is_ascii_digit()).collect();
    match digits.as_str() {
        "79" => Some("xss"),
        "918" => Some("ssrf"),
        "352" => Some("csrf"),
        "639" => Some("idor"),
        "200" => Some("info-leak"),
        "1004" => Some("js-readable-session"),
        "1021" => Some("no-csp"),
        "942" => Some("cors-cred-read"),
        _ => None,
    }
}

/// Lead kinds that name a primitive. `chain` is deliberately absent: the
/// playbook does not compose with itself, and a chain lead's truth is settled
/// by its own control, not by membership in a longer chain.
pub fn primitive_of_lead_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "idor" => Some("idor"),
        "exposure" => Some("info-leak"),
        _ => None,
    }
}

/// One side of a composition: the primitive, and — for the optimistic pass —
/// what to ask when this is the side that is *missing*.
struct Side {
    primitive: &'static str,
    /// Lead kind for the question that goes looking for this side.
    kind: &'static str,
    /// The question to file when this side is not held.
    ask: &'static str,
    /// Why the held side makes that question worth asking.
    why: &'static str,
}

/// One known-worthwhile composition: two primitives that, held together,
/// point at an impact bigger than either. `impact` names the severity the
/// composition *points at* — a lead carries no severity column on purpose:
/// the number is earned by the control, not asserted by the playbook.
///
/// Read backwards, the same pattern is the optimistic pass: one side held and
/// the other absent is not silence, it is the next question — the basis for a
/// chain someone should go look for (`Side::ask`).
struct Pattern {
    name: &'static str,
    impact: &'static str,
    /// The composed mechanism, stated as a question a verifier can spend time
    /// on — not as "these two might interact".
    question: &'static str,
    a: Side,
    b: Side,
}

const PLAYBOOK: &[Pattern] = &[
    Pattern {
        name: "xss-js-readable-session",
        impact: "critical",
        question: "One XSS plus a session cookie JavaScript can read is account \
                   takeover: step 2 of the chain is `document.cookie` leaving the page. \
                   Does the XSS reach a page where that cookie is set?",
        a: Side {
            primitive: "xss",
            kind: "injection",
            ask: "Is there reflected or stored XSS on the pages this session cookie \
                  travels with?",
            why: "the session is already readable from JavaScript, so an XSS there is \
                  account takeover — step 2 of the chain exists today",
        },
        b: Side {
            primitive: "js-readable-session",
            kind: "exposure",
            ask: "Is the session cookie set without HttpOnly, so JavaScript can read it?",
            why: "an XSS with nothing to steal is contained; this checks whether step 2 \
                  of the chain exists",
        },
    },
    Pattern {
        name: "cors-cred-idor",
        impact: "critical",
        question: "Wildcard-credentials CORS next to an IDOR: the other tenant's row \
                   becomes readable from attacker-controlled JavaScript in the victim's \
                   browser — cross-tenant exfiltration on the victim's session. Does the \
                   IDOR response actually arrive with the permissive CORS headers?",
        a: Side {
            primitive: "cors-cred-read",
            kind: "config",
            ask: "Do credentialed responses carry wildcard CORS \
                  (`Access-Control-Allow-Origin: *` with credentials)?",
            why: "an IDOR answer only same-origin scripts can read is one bug; if any \
                  origin can read it, it is cross-tenant exfiltration",
        },
        b: Side {
            primitive: "idor",
            kind: "idor",
            ask: "Do these credentialed endpoints answer other tenants' ids?",
            why: "wildcard-credentials CORS already hands any origin the victim's \
                  session; an IDOR decides what it can read",
        },
    },
    Pattern {
        name: "csrf-idor",
        impact: "high",
        question: "A state-changing IDOR without CSRF protection can be driven from any \
                   site the victim visits — no script access needed, the browser supplies \
                   the credentials. Does the mutating endpoint take no token?",
        a: Side {
            primitive: "csrf",
            kind: "authz",
            ask: "Does the mutating endpoint take an anti-CSRF token?",
            why: "a state-changing IDOR that any site can drive with the victim's \
                  cookies needs no script access",
        },
        b: Side {
            primitive: "idor",
            kind: "idor",
            ask: "Does the endpoint accept other tenants' ids in its mutations?",
            why: "missing CSRF alone is boring on an endpoint that only touches the \
                  caller's own data; an IDOR decides what the confused deputy can touch",
        },
    },
    Pattern {
        name: "ssrf-known-version",
        impact: "high",
        question: "SSRF plus a disclosed version: once the SSRF reaches the internal \
                   service, the banner pins which CVEs apply to it. Does the SSRF \
                   response echo an internal service's banner?",
        a: Side {
            primitive: "ssrf",
            kind: "other",
            ask: "Is there a parameter the server fetches a URL through?",
            why: "the version banner pins which CVEs apply once something can reach \
                  the service",
        },
        b: Side {
            primitive: "info-leak",
            kind: "exposure",
            ask: "Do the services behind this surface disclose versions in banners or \
                  headers?",
            why: "an SSRF that cannot identify its target is blind — a banner turns it \
                  into CVE pinning",
        },
    },
    Pattern {
        name: "xss-no-csp",
        impact: "high",
        question: "The landing page carries no CSP, so nothing backstops the payload — \
                   execution, not just reflection. Worth folding into the XSS's impact \
                   and remediation rather than reporting the missing header alone. Is \
                   the CSP-less page the one the XSS lands on?",
        a: Side {
            primitive: "xss",
            kind: "injection",
            ask: "Is there reflected or stored XSS on this CSP-less page?",
            why: "nothing backstops payload execution there — reflection would already \
                  be execution",
        },
        b: Side {
            primitive: "no-csp",
            kind: "config",
            ask: "Does the XSS landing page carry a Content-Security-Policy?",
            why: "execution is what makes an XSS land; a CSP is the backstop that \
                  would contain it",
        },
    },
];

/// One leg of a would-be chain: what it is, where it is, the primitive it
/// carries. `kind` is `"finding"` or `"lead"`; `tag` renders as `f#12`/`l#3`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub kind: &'static str,
    pub id: i64,
    pub primitive: &'static str,
    /// Findings know their host; leads carry only an endpoint. Two findings
    /// on different known hosts rarely compose — the chain would need a hop
    /// nobody has demonstrated — so [`candidates`] refuses those pairs.
    pub host: Option<String>,
}

impl Leg {
    fn tag(&self) -> String {
        format!(
            "{}#{}",
            if self.kind == "finding" { "f" } else { "l" },
            self.id
        )
    }
}

/// What the playbook proposes: the pair, the pattern it matched, and the lead
/// ready to file.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub pattern: &'static str,
    pub new: Leg,
    pub partner: Leg,
    pub title: String,
    pub rationale_md: String,
}

/// Every composition the playbook sees between `new` and any of `partners`.
///
/// Pairs are unordered — the new leg may sit on either side of a pattern — and
/// the returned titles are canonical (the pair sorted), so the same two legs
/// filed in either order produce the same candidate once, never twice. Pure:
/// the caller supplies the rows, tests supply the truth.
pub fn candidates(new: &Leg, partners: &[Leg]) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in PLAYBOOK {
        let other = if new.primitive == p.a.primitive {
            &p.b
        } else if new.primitive == p.b.primitive {
            &p.a
        } else {
            continue;
        };
        for partner in partners
            .iter()
            .filter(|l| l.primitive == other.primitive)
            .filter(|l| !(l.kind == new.kind && l.id == new.id))
        {
            // Both hosts known and different: refuse the pair. A chain across
            // hosts is real, but it needs a demonstrated hop, which is a lead
            // the agent writes — not a pattern this table can vouch for.
            if let (Some(a), Some(b)) = (&new.host, &partner.host)
                && a != b
            {
                continue;
            }
            // Canonical order, so arrival order cannot double-file a pair.
            let (lo, hi) = if (new.kind, new.id) <= (partner.kind, partner.id) {
                (new, partner)
            } else {
                (partner, new)
            };
            let title = format!("chain[{}] {} + {}", p.name, lo.tag(), hi.tag());
            if !seen.insert(title.clone()) {
                continue;
            }
            let rationale_md = format!(
                "Auto-proposed when {} ({}) landed next to {} ({}): pattern \
                 `{}` — composed impact {}.\n\n{}\n\nMembers: {} ({}), {} ({}).\n\n\
                 Settle it with a control that demonstrates the composition end to \
                 end — step 1's output spent as step 2's input, evidence flows for \
                 both legs — or refute it: a mitigation between the legs (scope, \
                 auth, same-site) kills the chain even when both bugs stand.",
                new.tag(),
                new.primitive,
                partner.tag(),
                partner.primitive,
                p.name,
                p.impact,
                p.question,
                lo.tag(),
                lo.primitive,
                hi.tag(),
                hi.primitive,
            );
            out.push(Candidate {
                pattern: p.name,
                new: new.clone(),
                partner: partner.clone(),
                title,
                rationale_md,
            });
        }
    }
    out
}

/// Every leg currently held that the playbook speaks for: findings whose CWE
/// classifies and whose status has not been walked back, leads whose kind
/// classifies and that were not refuted or ruled out.
fn held(conn: &Connection) -> Vec<Leg> {
    let mut legs = Vec::new();
    if let Ok(findings) = finding::list(conn) {
        for f in findings {
            if f.status == "false_positive" || f.status == "wont_fix" {
                continue;
            }
            if let Some(primitive) = f.cwe.as_deref().and_then(primitive_of_cwe) {
                legs.push(Leg {
                    kind: "finding",
                    id: f.id,
                    primitive,
                    host: f.host.clone(),
                });
            }
        }
    }
    if let Ok(leads) = lead::list(conn, None) {
        for l in leads {
            if l.status == "refuted" || l.ruling.as_deref() == Some("refuted") {
                continue;
            }
            // An open question is something to find, not something found: it
            // must not pair as though its kind were already held. Once it
            // verifies, it has *become* that primitive — a control is a
            // finding's worth of evidence — and pairs like any leg.
            if l.chain_id.is_some() && l.status != "verified" {
                continue;
            }
            if let Some(primitive) = primitive_of_lead_kind(&l.kind) {
                legs.push(Leg {
                    kind: "lead",
                    id: l.id,
                    primitive,
                    host: None,
                });
            }
        }
    }
    legs
}

/// One leg of a chain, as the database records it: what table it lives in and
/// its row id. `kind` is `"finding"` or `"lead"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub kind: String,
    pub id: i64,
}

/// A question filed under a chain: an ordinary lead, with the chain's id, so a
/// dispatched agent can pick it up as work and the chain can be reassembled
/// from it later.
#[derive(Clone, Debug)]
pub struct ChainQuestion {
    pub kind: String,
    pub title: String,
    pub rationale_md: String,
}

/// A chain as a caller files one — the model pass arrives here, with whatever
/// composition it saw; the playbook arrives here too, with the pairs it
/// matched. One write path, so both are the same shape on disk.
#[derive(Clone, Debug)]
pub struct NewChain {
    pub title: String,
    pub rationale_md: String,
    pub endpoint: Option<String>,
    pub members: Vec<Member>,
    pub questions: Vec<ChainQuestion>,
}

/// What filing a chain produced.
#[derive(Clone, Debug, Default)]
pub struct FiledChain {
    pub id: i64,
    /// False when a chain with this title already existed and only its missing
    /// questions were added.
    pub created: bool,
    pub question_ids: Vec<i64>,
}

#[derive(Debug)]
pub enum ChainError {
    /// A structurally bad chain: empty title or rationale, no members, an
    /// unknown member kind, a member that does not exist, or a question with
    /// an unknown kind.
    BadValue(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::BadValue(why) => write!(f, "{why}"),
            ChainError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<rusqlite::Error> for ChainError {
    fn from(e: rusqlite::Error) -> Self {
        ChainError::Db(e)
    }
}

impl From<lead::LeadError> for ChainError {
    fn from(e: lead::LeadError) -> Self {
        match e {
            lead::LeadError::Db(db) => ChainError::Db(db),
            other => ChainError::BadValue(other.to_string()),
        }
    }
}

/// The one write path for chains: the container lead, its members, and its
/// questions, committed together. Idempotent on title — a chain that already
/// exists takes only the questions it does not have yet, so the model pass can
/// run as often as it likes without doubling the ledger.
pub fn file_chain(conn: &Connection, new: &NewChain, now: i64) -> Result<FiledChain, ChainError> {
    if new.title.trim().is_empty() || new.rationale_md.trim().is_empty() {
        return Err(ChainError::BadValue(
            "a chain needs a title and a rationale".to_string(),
        ));
    }
    if new.members.is_empty() {
        return Err(ChainError::BadValue(
            "a chain needs at least one member".to_string(),
        ));
    }
    for m in &new.members {
        if m.kind != "finding" && m.kind != "lead" {
            return Err(ChainError::BadValue(format!(
                "member kind must be \"finding\" or \"lead\", got {:?}",
                m.kind
            )));
        }
        let exists = if m.kind == "finding" {
            finding::get(conn, m.id)?.is_some()
        } else {
            lead::get(conn, m.id)?.is_some()
        };
        if !exists {
            return Err(ChainError::BadValue(format!(
                "member {} #{} does not exist",
                m.kind, m.id
            )));
        }
    }
    for q in &new.questions {
        if !lead::LEAD_KINDS.contains(&q.kind.as_str()) {
            return Err(ChainError::BadValue(format!(
                "question kind {:?} is not a lead kind — known: {}",
                q.kind,
                lead::LEAD_KINDS.join(", ")
            )));
        }
        if q.title.trim().is_empty() || q.rationale_md.trim().is_empty() {
            return Err(ChainError::BadValue(
                "a question needs a title and a rationale".to_string(),
            ));
        }
    }

    // The container, or the one that already carries this title.
    let (chain_id, created) = match conn
        .query_row(
            "SELECT id FROM lead WHERE kind = 'chain' AND title = ?1",
            [&new.title],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    {
        Some(id) => (id, false),
        None => {
            let id = lead::propose(
                conn,
                &lead::NewLead {
                    kind: "chain".into(),
                    title: new.title.trim().to_string(),
                    rationale_md: new.rationale_md.clone(),
                    endpoint: new.endpoint.clone(),
                    flow_id: None,
                    chain_id: None,
                },
                now,
            )?;
            for m in &new.members {
                conn.execute(
                    "INSERT OR IGNORE INTO chain_member (chain_id, leg_kind, leg_id) \
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![id, m.kind, m.id],
                )?;
            }
            (id, true)
        }
    };

    // Questions: only the ones this chain does not already ask.
    let existing: Vec<String> = lead::list_for_chain(conn, chain_id)?
        .into_iter()
        .map(|l| l.title)
        .collect();
    let mut question_ids = Vec::new();
    for q in &new.questions {
        if existing.contains(&q.title) {
            continue;
        }
        question_ids.push(lead::propose(
            conn,
            &lead::NewLead {
                kind: q.kind.clone(),
                title: q.title.trim().to_string(),
                rationale_md: q.rationale_md.clone(),
                endpoint: None,
                flow_id: None,
                chain_id: Some(chain_id),
            },
            now,
        )?);
    }

    Ok(FiledChain {
        id: chain_id,
        created,
        question_ids,
    })
}

/// What one trigger of the pass filed: full chains (both legs present) and
/// questions (one leg present, the other worth going looking for).
#[derive(Clone, Debug, Default)]
pub struct ChainPass {
    pub chains: Vec<i64>,
    pub questions: Vec<i64>,
}

/// The optimistic pass: a leg just landed, no partner for some pattern it
/// belongs to — so ask for the partner, under a chain that carries the basis.
///
/// This is "we got this finding, where should I focus next?": the questions
/// are ordinary leads parented to a basis chain, which is exactly the shape a
/// dispatched research agent picks up. When the partner lands later, the
/// retrospective pass pairs the two into a full chain; the question settles on
/// its own evidence like any lead.
fn optimistic(conn: &Connection, basis: &Leg, held: &[Leg], now: i64) -> Vec<i64> {
    let mut wanted = Vec::new();
    for p in PLAYBOOK {
        // The side the basis is *not* on is the leg to go find.
        let missing = if basis.primitive == p.a.primitive {
            &p.b
        } else if basis.primitive == p.b.primitive {
            &p.a
        } else {
            continue;
        };
        // Partner already held: the retrospective pass owns that pattern.
        if held.iter().any(|l| l.primitive == missing.primitive) {
            continue;
        }
        wanted.push((p, missing));
    }
    if wanted.is_empty() {
        return Vec::new();
    }

    let names: Vec<&str> = wanted.iter().map(|(p, _)| p.name).collect();
    let basis_tag = basis.tag();
    let chain = NewChain {
        title: format!("chain[basis] {} ({})", basis.tag(), basis.primitive),
        rationale_md: format!(
            "Optimistic chain: {basis_tag} is a {}. The playbook sees compositions \
             whose other leg is not held yet — {}. Each question below is one leg to go \
             find; when it lands, the chain pass pairs the two automatically. Work the \
             questions in any order; settle each on its own evidence.",
            basis.primitive,
            names.join(", ")
        ),
        endpoint: basis.host.clone(),
        members: vec![Member {
            kind: basis.kind.to_string(),
            id: basis.id,
        }],
        questions: wanted
            .iter()
            .map(|(p, missing)| ChainQuestion {
                kind: missing.kind.to_string(),
                title: missing.ask.to_string(),
                rationale_md: format!(
                    "Asking for `{}`: {} (basis: {basis_tag}, a {}).",
                    p.name, missing.why, basis.primitive
                ),
            })
            .collect(),
    };
    match file_chain(conn, &chain, now) {
        Ok(filed) => filed.question_ids,
        Err(_) => Vec::new(),
    }
}

/// Propose chains for a freshly-committed finding: the pairs that are already
/// complete, then the questions for the pairs that are not. Files what
/// composes, deduped by title against the ledger, and returns what it filed.
///
/// Fails into silence, like every capture-path extra: a chain problem must
/// not cost the finding its landing, and a lost candidate is a triage line,
/// not evidence.
pub fn propose_for_finding(conn: &Connection, id: i64, f: &NewFinding, now: i64) -> ChainPass {
    if f.status == "false_positive" || f.status == "wont_fix" {
        return ChainPass::default();
    }
    let Some(primitive) = f.cwe.as_deref().and_then(primitive_of_cwe) else {
        return ChainPass::default();
    };
    let new = Leg {
        kind: "finding",
        id,
        primitive,
        host: f.host.clone(),
    };
    run(conn, &new, f.host.clone(), now)
}

/// Propose chains for a lead — new, or just settled as verified, which is when
/// a primitive becomes load-bearing. A `chain` lead classifies as nothing and
/// returns early: the playbook never composes with itself.
pub fn propose_for_lead(conn: &Connection, l: &Lead, now: i64) -> ChainPass {
    let Some(primitive) = primitive_of_lead_kind(&l.kind) else {
        return ChainPass::default();
    };
    let new = Leg {
        kind: "lead",
        id: l.id,
        primitive,
        host: None,
    };
    run(conn, &new, l.endpoint.clone(), now)
}

/// Both directions over one basis leg: the complete pairs, then the questions
/// for the incomplete ones.
fn run(conn: &Connection, new: &Leg, endpoint: Option<String>, now: i64) -> ChainPass {
    let held = held(conn);
    let mut pass = ChainPass::default();

    for c in candidates(new, &held) {
        let known = conn
            .query_row(
                "SELECT 1 FROM lead WHERE kind = 'chain' AND title = ?1",
                [&c.title],
                |_| Ok(()),
            )
            .optional()
            .unwrap_or(None);
        if known.is_some() {
            continue;
        }
        let Ok(filed) = file_chain(
            conn,
            &NewChain {
                title: c.title.clone(),
                rationale_md: c.rationale_md.clone(),
                endpoint: endpoint.clone(),
                members: vec![
                    Member {
                        kind: c.new.kind.to_string(),
                        id: c.new.id,
                    },
                    Member {
                        kind: c.partner.kind.to_string(),
                        id: c.partner.id,
                    },
                ],
                questions: Vec::new(),
            },
            now,
        ) else {
            break;
        };
        pass.chains.push(filed.id);
    }

    pass.questions = optimistic(conn, new, &held, now);
    pass
}

/// A chain as the model pass sees it: the container lead, its members, and its
/// questions.
#[derive(Clone, Debug)]
pub struct ReviewChain {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub members: Vec<Member>,
    pub questions: Vec<Lead>,
}

/// One finding, compacted for the brief.
#[derive(Clone, Debug)]
pub struct ReviewFinding {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub cwe: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub primitive: Option<&'static str>,
}

/// The brief for the model pass: everything held, compacted to what reasoning
/// about compositions needs. Findings come without their prose — titles and
/// classification; the model reads a write-up through `get_finding` when one
/// matters. Leads come whole: their rationales are the reasoning of the run,
/// and compositions often live there.
#[derive(Clone, Debug, Default)]
pub struct Review {
    /// The playbook's pattern names, so the pass knows the classics are
    /// already covered and spends its attention elsewhere.
    pub playbook: Vec<&'static str>,
    /// One line per finding.
    pub findings: Vec<ReviewFinding>,
    /// Every lead, whole, including chain containers and questions.
    pub leads: Vec<Lead>,
    /// Every chain with its members and questions.
    pub chains: Vec<ReviewChain>,
}

/// Assemble the brief (see [`Review`]). Pure read.
pub fn review(conn: &Connection) -> Review {
    let findings = finding::list(conn)
        .unwrap_or_default()
        .into_iter()
        .map(|f| ReviewFinding {
            primitive: f.cwe.as_deref().and_then(primitive_of_cwe),
            id: f.id,
            title: f.title,
            severity: f.severity,
            status: f.status,
            cwe: f.cwe,
            host: f.host,
            path: f.path,
        })
        .collect();
    let leads = lead::list(conn, None).unwrap_or_default();
    let chains = leads
        .iter()
        .filter(|l| l.kind == "chain")
        .filter_map(|l| {
            let members: Vec<Member> = conn
                .prepare(
                    "SELECT leg_kind, leg_id FROM chain_member WHERE chain_id = ?1 \
                     ORDER BY leg_kind, leg_id",
                )
                .and_then(|mut s| {
                    s.query_map([l.id], |r| {
                        Ok(Member {
                            kind: r.get(0)?,
                            id: r.get(1)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
                })
                .ok()?;
            Some(ReviewChain {
                id: l.id,
                title: l.title.clone(),
                status: l.status.clone(),
                members,
                questions: lead::list_for_chain(conn, l.id).unwrap_or_default(),
            })
        })
        .collect();
    Review {
        playbook: PLAYBOOK.iter().map(|p| p.name).collect(),
        findings,
        leads,
        chains,
    }
}

/// One chain with its members and questions.
pub fn chain(conn: &Connection, id: i64) -> Option<ReviewChain> {
    let l = lead::get(conn, id).ok().flatten()?;
    if l.kind != "chain" {
        return None;
    }
    review(conn).chains.into_iter().find(|c| c.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    fn leg(kind: &'static str, id: i64, primitive: &'static str) -> Leg {
        Leg {
            kind,
            id,
            primitive,
            host: None,
        }
    }

    fn finding(cwe: Option<&str>, host: Option<&str>) -> NewFinding {
        NewFinding {
            title: "t".into(),
            severity: "medium".into(),
            status: "confirmed".into(),
            cwe: cwe.map(str::to_string),
            host: host.map(str::to_string),
            description_md: "d".into(),
            ..NewFinding::default()
        }
    }

    #[test]
    fn classification_covers_the_scanners_own_cwes() {
        assert_eq!(primitive_of_cwe("79"), Some("xss"));
        assert_eq!(primitive_of_cwe("CWE-918"), Some("ssrf"));
        assert_eq!(primitive_of_cwe("1004"), Some("js-readable-session"));
        assert_eq!(primitive_of_cwe("1021"), Some("no-csp"));
        assert_eq!(primitive_of_cwe("942"), Some("cors-cred-read"));
        assert_eq!(primitive_of_cwe("9999"), None);
        assert_eq!(primitive_of_lead_kind("idor"), Some("idor"));
        assert_eq!(primitive_of_lead_kind("chain"), None);
    }

    #[test]
    fn a_pair_proposes_the_composed_question() {
        let out = candidates(
            &leg("finding", 3, "xss"),
            &[
                leg("finding", 9, "js-readable-session"),
                leg("finding", 10, "idor"),
            ],
        );
        assert_eq!(out.len(), 1, "idor composes with nothing here");
        assert_eq!(out[0].pattern, "xss-js-readable-session");
        assert!(out[0].title == "chain[xss-js-readable-session] f#3 + f#9");
        assert!(out[0].rationale_md.contains("account takeover"));
        assert!(out[0].rationale_md.contains("f#9 (js-readable-session)"));
        assert!(out[0].rationale_md.contains("control"));
    }

    #[test]
    fn either_arrival_order_yields_the_same_candidate_once() {
        // xss + idor is not a pattern, whichever side arrives: both empty.
        assert!(candidates(&leg("finding", 3, "xss"), &[leg("lead", 7, "idor")]).is_empty());
        assert!(candidates(&leg("lead", 7, "idor"), &[leg("finding", 3, "xss")]).is_empty());

        let a = candidates(
            &leg("finding", 3, "xss"),
            &[leg("finding", 9, "js-readable-session")],
        );
        let b = candidates(
            &leg("finding", 9, "js-readable-session"),
            &[leg("finding", 3, "xss")],
        );
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(a[0].title, b[0].title);
        assert_eq!(a[0].title, "chain[xss-js-readable-session] f#3 + f#9");
    }

    #[test]
    fn different_known_hosts_do_not_compose() {
        let out = candidates(
            &Leg {
                kind: "finding",
                id: 1,
                primitive: "xss",
                host: Some("a.target.com".into()),
            },
            &[Leg {
                kind: "finding",
                id: 2,
                primitive: "no-csp",
                host: Some("b.target.com".into()),
            }],
        );
        assert!(out.is_empty(), "the hop between hosts is undemonstrated");

        let out = candidates(
            &Leg {
                kind: "finding",
                id: 1,
                primitive: "xss",
                host: Some("a.target.com".into()),
            },
            &[leg("finding", 2, "no-csp")],
        );
        assert_eq!(out.len(), 1, "an unknown host is not a refusal");
    }

    #[test]
    fn filing_dedupes_by_pair_and_never_refiles() {
        let c = conn();
        let idor_id = finding::insert(&c, &finding(Some("639"), Some("t.com")), 1).unwrap();
        // An IDOR alone files no full chain — but it does ask its optimistic
        // questions, asserted separately below.
        let pass = propose_for_finding(&c, idor_id, &finding(Some("639"), Some("t.com")), 1);
        assert!(pass.chains.is_empty(), "nothing to compose with yet");

        let cors_id = finding::insert(&c, &finding(Some("942"), Some("t.com")), 2).unwrap();
        let second = propose_for_finding(&c, cors_id, &finding(Some("942"), Some("t.com")), 2);
        assert_eq!(second.chains.len(), 1, "wildcard-credentials CORS + IDOR");
        assert!(
            second.questions.is_empty(),
            "the partner is held, so nothing is asked for"
        );
        let chain = lead::get(&c, second.chains[0]).unwrap().unwrap();
        assert_eq!(chain.kind, "chain");
        assert_eq!(chain.status, "proposed");
        assert!(chain.rationale_md.contains("cross-tenant exfiltration"));

        // The same pair re-proposed from the other direction files nothing new.
        let again = propose_for_finding(&c, idor_id, &finding(Some("639"), Some("t.com")), 3);
        assert!(
            again.chains.is_empty(),
            "the title already exists in the ledger"
        );
        // The full chain exists once; the idor basis chain is its own lead.
        let full = lead::list(&c, None)
            .unwrap()
            .iter()
            .filter(|l| l.kind == "chain" && l.title.contains("cors-cred-idor"))
            .count();
        assert_eq!(full, 1);
    }

    #[test]
    fn a_verified_lead_composes_and_a_refuted_one_does_not() {
        let c = conn();
        let lead_id = lead::propose(
            &c,
            &lead::NewLead {
                kind: "exposure".into(),
                title: "Internal banners on the status page".into(),
                rationale_md: "r".into(),
                endpoint: None,
                flow_id: None,
                chain_id: None,
            },
            1,
        )
        .unwrap();
        // An XSS lands with no session/CSP partner: no pair, but two
        // optimistic questions under one basis chain.
        let xss_id = finding::insert(&c, &finding(Some("79"), Some("t.com")), 2).unwrap();
        let xss_pass = propose_for_finding(&c, xss_id, &finding(Some("79"), Some("t.com")), 2);
        assert!(xss_pass.chains.is_empty());
        assert_eq!(xss_pass.questions.len(), 2, "session readability, CSP");
        let basis = lead::get(&c, xss_pass.questions[0])
            .unwrap()
            .unwrap()
            .chain_id
            .unwrap();
        let basis_chain = lead::get(&c, basis).unwrap().unwrap();
        assert_eq!(basis_chain.kind, "chain");
        assert!(basis_chain.title.contains("(xss)"));
        assert_eq!(lead::list_for_chain(&c, basis).unwrap().len(), 2);

        // The exposure lead makes the SSRF pattern complete when one lands.
        let ssrf_id = finding::insert(&c, &finding(Some("918"), Some("t.com")), 3).unwrap();
        let filed = propose_for_finding(&c, ssrf_id, &finding(Some("918"), Some("t.com")), 4);
        assert_eq!(filed.chains.len(), 1, "ssrf + info-leak composes");

        // The exposure lead refuted: no longer a partner for anything new.
        lead::record_verdict(
            &c,
            lead_id,
            "refuted",
            Some("banners are the CDN's, not the origin's"),
            Some("same page via direct origin connection shows no banner"),
            5,
        )
        .unwrap();
        finding::delete(&c, ssrf_id).unwrap();
        let filed = propose_for_finding(&c, 10, &finding(Some("918"), Some("t.com")), 6);
        assert!(filed.chains.is_empty(), "the info-leak leg was refuted");
    }

    #[test]
    fn the_model_pass_files_its_own_chains_and_is_idempotent() {
        let c = conn();
        let f1 = finding::insert(&c, &finding(Some("79"), Some("t.com")), 1).unwrap();
        let l1 = lead::propose(
            &c,
            &lead::NewLead {
                kind: "logic".into(),
                title: "Password reset does not invalidate old sessions".into(),
                rationale_md: "r".into(),
                endpoint: None,
                flow_id: None,
                chain_id: None,
            },
            2,
        )
        .unwrap();

        // A composition no table will ever know: XSS + uninvalidated session.
        let filed = file_chain(
            &c,
            &NewChain {
                title: "chain[xss-stale-session] f#1 + l#2".into(),
                rationale_md: "The XSS outlives the password reset: the reset \
                               invalidates nothing the attacker already holds."
                    .into(),
                endpoint: Some("t.com".into()),
                members: vec![
                    Member {
                        kind: "finding".into(),
                        id: f1,
                    },
                    Member {
                        kind: "lead".into(),
                        id: l1,
                    },
                ],
                questions: vec![ChainQuestion {
                    kind: "authz".into(),
                    title: "Does the reset revoke existing session cookies?".into(),
                    rationale_md: "If it does not, the XSS survives the reset.".into(),
                }],
            },
            3,
        )
        .unwrap();
        assert!(filed.created);
        assert_eq!(filed.question_ids.len(), 1);

        let full = chain(&c, filed.id).unwrap();
        assert_eq!(full.members.len(), 2);
        assert_eq!(full.questions.len(), 1);
        assert_eq!(full.questions[0].kind, "authz");
        assert_eq!(full.questions[0].chain_id, Some(filed.id));

        // Filing the same chain again adds nothing but stays green.
        let again = file_chain(
            &c,
            &NewChain {
                title: "chain[xss-stale-session] f#1 + l#2".into(),
                rationale_md: "same chain, run twice".into(),
                endpoint: None,
                members: vec![Member {
                    kind: "finding".into(),
                    id: f1,
                }],
                questions: vec![ChainQuestion {
                    kind: "authz".into(),
                    title: "Does the reset revoke existing session cookies?".into(),
                    rationale_md: "already asked".into(),
                }],
            },
            4,
        )
        .unwrap();
        assert!(!again.created, "the title matched an existing chain");
        assert!(
            again.question_ids.is_empty(),
            "the question was already asked"
        );

        // Validation: members must exist, a chain needs one.
        assert!(matches!(
            file_chain(
                &c,
                &NewChain {
                    title: "x".into(),
                    rationale_md: "r".into(),
                    endpoint: None,
                    members: vec![Member {
                        kind: "finding".into(),
                        id: 99,
                    }],
                    questions: vec![],
                },
                5
            ),
            Err(ChainError::BadValue(_))
        ));
        assert!(matches!(
            file_chain(
                &c,
                &NewChain {
                    title: "x".into(),
                    rationale_md: "r".into(),
                    endpoint: None,
                    members: vec![],
                    questions: vec![],
                },
                5
            ),
            Err(ChainError::BadValue(_))
        ));

        // And the brief carries it all for the next pass.
        let review = review(&c);
        assert!(review.playbook.contains(&"xss-js-readable-session"));
        assert!(review.findings.iter().any(|f| f.primitive == Some("xss")));
        let brief_chain = review
            .chains
            .iter()
            .find(|ch| ch.title == "chain[xss-stale-session] f#1 + l#2")
            .unwrap();
        assert_eq!(brief_chain.questions.len(), 1);
        assert!(
            review
                .leads
                .iter()
                .any(|l| l.chain_id == Some(brief_chain.id)),
            "the question lead is in the brief, parented"
        );
    }

    #[test]
    fn false_positives_and_unclassifiable_rows_propose_nothing() {
        let c = conn();
        assert!(
            propose_for_finding(
                &c,
                1,
                &NewFinding {
                    status: "false_positive".into(),
                    ..finding(Some("79"), Some("t.com"))
                },
                1
            )
            .chains
            .is_empty()
        );

        let no_cwe = finding(None, Some("t.com"));
        assert!(propose_for_finding(&c, 2, &no_cwe, 2).chains.is_empty());

        let logic = lead::propose(
            &c,
            &lead::NewLead {
                kind: "logic".into(),
                title: "t".into(),
                rationale_md: "r".into(),
                endpoint: None,
                flow_id: None,
                chain_id: None,
            },
            3,
        )
        .unwrap();
        let stored = lead::get(&c, logic).unwrap().unwrap();
        assert!(propose_for_lead(&c, &stored, 4).chains.is_empty());
    }
}
