//! Policy: the engagement's guardrails, as data the engine enforces.
//!
//! Autonomy without a floor is just automated trouble. Policy is the floor:
//! a per-host send rate and a list of URL patterns replay may never touch —
//! the out-of-bounds list every bug-bounty program publishes and every agent
//! will eventually wander into. Because enforcement sits in the engine's send
//! path, it binds every caller equally: the TUI, the MCP tools, and the
//! orchestrator's verifier agents.
//!
//! The default is permissive on purpose. A hand-driven session should notice
//! nothing; an agent's free hand is exactly as wide as the policy drawn here.
//! Patterns are checked with the `regex` crate — unanchored, like scope's
//! regex host rules, so write full anchors when a pattern means them.

use rusqlite::{Connection, params};

/// The single policy row.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// Max sends per second per host on the replay path. `None` = unlimited.
    pub rate_per_sec: Option<f64>,
    pub note: Option<String>,
}

/// One out-of-bounds rule. Today the only kind is `forbid_url_regex`; the
/// column exists so later shapes join the same table.
#[derive(Clone, Debug)]
pub struct PolicyRule {
    pub id: i64,
    pub kind: String,
    pub pattern: String,
    pub note: Option<String>,
    pub enabled: bool,
}

/// The rule vocabulary. The engine refuses to store anything else — a typo'd
/// kind must fail at write time, not silently never match at send time.
pub const RULE_KINDS: &[&str] = &["forbid_url_regex"];

#[derive(Debug)]
pub enum PolicyError {
    /// A pattern that cannot compile, or a kind outside [`RULE_KINDS`].
    BadRule(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::BadRule(why) => write!(f, "{why}"),
            PolicyError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PolicyError {}

pub fn get(conn: &Connection) -> rusqlite::Result<Policy> {
    conn.query_row(
        "SELECT rate_per_sec, note FROM policy WHERE id = 1",
        [],
        |r| {
            Ok(Policy {
                rate_per_sec: r.get(0)?,
                note: r.get(1)?,
            })
        },
    )
}

/// Set the per-host send ceiling. `None` (or `0`) lifts it.
pub fn set_rate(conn: &Connection, rate_per_sec: Option<f64>) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE policy SET rate_per_sec = ?1 WHERE id = 1",
        [rate_per_sec],
    )
}

pub fn set_note(conn: &Connection, note: Option<&str>) -> rusqlite::Result<usize> {
    conn.execute("UPDATE policy SET note = ?1 WHERE id = 1", [note])
}

pub fn rules(conn: &Connection) -> rusqlite::Result<Vec<PolicyRule>> {
    let mut stmt =
        conn.prepare("SELECT id, kind, pattern, note, enabled FROM policy_rule ORDER BY id")?;
    stmt.query_map([], |r| {
        Ok(PolicyRule {
            id: r.get(0)?,
            kind: r.get(1)?,
            pattern: r.get(2)?,
            note: r.get(3)?,
            enabled: r.get::<_, i64>(4)? != 0,
        })
    })?
    .collect()
}

/// Add a rule, validating that the kind is known and the pattern compiles —
/// a rule that cannot match is a guardrail that does not exist.
pub fn add_rule(
    conn: &Connection,
    kind: &str,
    pattern: &str,
    note: Option<&str>,
) -> Result<i64, PolicyError> {
    if !RULE_KINDS.contains(&kind) {
        return Err(PolicyError::BadRule(format!(
            "unknown rule kind “{kind}” — known: {}",
            RULE_KINDS.join(", ")
        )));
    }
    let compiled = regex::Regex::new(pattern)
        .map_err(|e| PolicyError::BadRule(format!("pattern does not compile: {e}")))?;
    // Empty-string compile-check evasion: `""` matches every URL, which the
    // caller almost never means.
    if compiled.is_match("") && pattern != "^$" {
        return Err(PolicyError::BadRule(
            "pattern matches everything — anchor it, e.g. ^https://…".to_string(),
        ));
    }
    conn.execute(
        "INSERT INTO policy_rule (kind, pattern, note) VALUES (?1, ?2, ?3)",
        params![kind, pattern, note],
    )
    .map_err(PolicyError::Db)?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_rule(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM policy_rule WHERE id = ?1", [id])
}

pub fn set_rule_enabled(conn: &Connection, id: i64, enabled: bool) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE policy_rule SET enabled = ?2 WHERE id = ?1",
        params![id, enabled as i64],
    )
}

/// The first enabled rule the URL violates, or `None` when it may pass.
/// Rules are evaluated in id order, so the oldest rule wins a tie — stable
/// reporting beats clever precedence.
pub fn violation(rules: &[PolicyRule], url: &str) -> Option<PolicyRule> {
    rules
        .iter()
        .find(|rule| {
            rule.enabled
                && rule.kind == "forbid_url_regex"
                && regex::Regex::new(&rule.pattern)
                    .map(|re| re.is_match(url))
                    .unwrap_or(false)
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    #[test]
    fn policy_row_exists_and_is_permissive_by_default() {
        let c = conn();
        let p = get(&c).unwrap();
        assert_eq!(p.rate_per_sec, None);
        assert_eq!(p.note, None);
        assert!(rules(&c).unwrap().is_empty());
    }

    #[test]
    fn rate_and_rules_round_trip() {
        let c = conn();
        set_rate(&c, Some(2.5)).unwrap();
        assert_eq!(get(&c).unwrap().rate_per_sec, Some(2.5));
        set_rate(&c, None).unwrap();
        assert_eq!(
            get(&c).unwrap().rate_per_sec,
            None,
            "None lifts the ceiling"
        );

        let id = add_rule(
            &c,
            "forbid_url_regex",
            r"^https://target\.com/pay",
            Some("money"),
        )
        .unwrap();
        let list = rules(&c).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pattern, r"^https://target\.com/pay");
        assert_eq!(list[0].note.as_deref(), Some("money"));
        assert!(list[0].enabled);

        set_rule_enabled(&c, id, false).unwrap();
        assert!(!rules(&c).unwrap()[0].enabled);
        delete_rule(&c, id).unwrap();
        assert!(rules(&c).unwrap().is_empty());
    }

    #[test]
    fn a_rule_must_be_known_and_compile() {
        let c = conn();
        let err = add_rule(&c, "forbid_url", "x", None).unwrap_err();
        assert!(matches!(err, PolicyError::BadRule(_)), "{err}");
        let err = add_rule(&c, "forbid_url_regex", "(unclosed", None).unwrap_err();
        assert!(matches!(err, PolicyError::BadRule(_)), "{err}");
        // A pattern that matches everything guards nothing.
        let err = add_rule(&c, "forbid_url_regex", "", None).unwrap_err();
        assert!(matches!(err, PolicyError::BadRule(_)), "{err}");
        assert!(
            rules(&c).unwrap().is_empty(),
            "refused rules must not persist"
        );
    }

    #[test]
    fn violation_matches_only_enabled_rules_of_known_kind() {
        let c = conn();
        let hit = add_rule(&c, "forbid_url_regex", r"/pay", None).unwrap();
        add_rule(&c, "forbid_url_regex", r"^https://out\.of/scope", None).unwrap();

        let list = rules(&c).unwrap();
        assert!(violation(&list, "https://target.com/pay?x=1").unwrap().id == hit);
        assert!(violation(&list, "https://target.com/api").is_none());
        assert!(violation(&list, "https://out.of/scope").is_some());

        // Disabled rules stop binding the moment they are disabled.
        set_rule_enabled(&c, hit, false).unwrap();
        let list = rules(&c).unwrap();
        assert!(violation(&list, "https://target.com/pay").is_none());
    }
}
