//! Scope: which assets an engagement is actually about.
//!
//! Scope is a **view filter**, not a property of captured traffic. Selecting a
//! scope narrows the history to that asset's resources; nothing is dropped at
//! capture time and no `in_scope` column is stored, because scope is mutable and
//! storing it would mean rewriting millions of rows on every rule edit.
//!
//! Semantics — **inclusion is the lever**:
//!
//! - no include rules → everything is in scope
//! - any include rule → only matching assets are in scope
//! - excludes carve holes and always beat includes
//!
//! Excludes winning outright is what makes the result independent of rule order,
//! so "why is this host missing?" never depends on how the list is sorted.

use std::net::IpAddr;

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Include,
    Exclude,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Include => "include",
            Action::Exclude => "exclude",
        }
    }

    fn parse(s: &str) -> Result<Self, ScopeError> {
        match s {
            "include" => Ok(Action::Include),
            "exclude" => Ok(Action::Exclude),
            other => Err(ScopeError::UnknownAction(other.to_string())),
        }
    }
}

/// How a rule's `host_pattern` should be interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKind {
    /// `*` matches any run of characters, `?` exactly one. Case-insensitive,
    /// since hostnames are.
    Glob,
    Regex,
    /// The host must be an IP literal inside the given network.
    Cidr,
}

impl HostKind {
    fn as_str(self) -> &'static str {
        match self {
            HostKind::Glob => "glob",
            HostKind::Regex => "regex",
            HostKind::Cidr => "cidr",
        }
    }

    fn parse(s: &str) -> Result<Self, ScopeError> {
        match s {
            "glob" => Ok(HostKind::Glob),
            "regex" => Ok(HostKind::Regex),
            "cidr" => Ok(HostKind::Cidr),
            other => Err(ScopeError::UnknownHostKind(other.to_string())),
        }
    }
}

/// A conjunction: every constraint that is `Some` must match. All-`None` matches
/// everything, which is a legitimate way to write "include the world".
#[derive(Clone, Debug, Default)]
pub struct RuleSpec {
    pub host: Option<(HostKind, String)>,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
}

impl RuleSpec {
    pub fn host(kind: HostKind, pattern: impl Into<String>) -> Self {
        Self {
            host: Some((kind, pattern.into())),
            ..Default::default()
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = Some(prefix.into());
        self
    }
}

#[derive(Clone, Debug)]
pub struct ScopeRule {
    pub id: i64,
    pub action: Action,
    pub spec: RuleSpec,
    pub enabled: bool,
    pub from_node_id: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct Scope {
    pub id: i64,
    pub name: String,
    pub is_active: bool,
}

/// What a rule is tested against. `port` is always resolved (from the URI or the
/// scheme default) so a port constraint means the same thing whether or not the
/// client wrote the port out.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
}

#[derive(Debug)]
pub enum ScopeError {
    Db(rusqlite::Error),
    BadRegex(String),
    BadCidr(String),
    UnknownAction(String),
    UnknownHostKind(String),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::Db(e) => write!(f, "database: {e}"),
            ScopeError::BadRegex(p) => write!(f, "invalid host regex: {p}"),
            ScopeError::BadCidr(p) => write!(f, "invalid CIDR: {p}"),
            ScopeError::UnknownAction(a) => write!(f, "unknown scope action: {a}"),
            ScopeError::UnknownHostKind(k) => write!(f, "unknown host kind: {k}"),
        }
    }
}

impl From<rusqlite::Error> for ScopeError {
    fn from(e: rusqlite::Error) -> Self {
        ScopeError::Db(e)
    }
}

// --- matching ---

#[derive(Debug)]
enum HostMatcher {
    Glob(String),
    Regex(Regex),
    Cidr(IpAddr, u8),
}

impl HostMatcher {
    fn compile(kind: HostKind, pattern: &str) -> Result<Self, ScopeError> {
        match kind {
            HostKind::Glob => Ok(HostMatcher::Glob(pattern.to_ascii_lowercase())),
            HostKind::Regex => Regex::new(pattern)
                .map(HostMatcher::Regex)
                .map_err(|_| ScopeError::BadRegex(pattern.to_string())),
            HostKind::Cidr => {
                let (addr, bits) = parse_cidr(pattern)
                    .ok_or_else(|| ScopeError::BadCidr(pattern.to_string()))?;
                Ok(HostMatcher::Cidr(addr, bits))
            }
        }
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            HostMatcher::Glob(pattern) => glob_match(pattern, &host.to_ascii_lowercase()),
            HostMatcher::Regex(re) => re.is_match(host),
            // Only meaningful for IP-literal hosts; a name never matches.
            HostMatcher::Cidr(net, bits) => host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip_in_network(ip, *net, *bits)),
        }
    }
}

#[derive(Debug)]
struct Compiled {
    host: Option<HostMatcher>,
    port: Option<u16>,
    path_prefix: Option<String>,
}

impl Compiled {
    fn matches(&self, target: &Target) -> bool {
        if let Some(host) = &self.host
            && !host.matches(target.host)
        {
            return false;
        }
        if let Some(port) = self.port
            && port != target.port
        {
            return false;
        }
        if let Some(prefix) = &self.path_prefix
            && !path_has_prefix(target.path, prefix)
        {
            return false;
        }
        true
    }
}

/// A compiled scope, ready to test requests against.
#[derive(Debug, Default)]
pub struct Matcher {
    includes: Vec<Compiled>,
    excludes: Vec<Compiled>,
}

impl Matcher {
    /// Compile a rule set. Disabled rules are skipped.
    ///
    /// Returns `Err` on a malformed pattern rather than silently dropping the
    /// rule: a dropped *exclude* would quietly widen scope, which is the one
    /// failure here with real consequences.
    pub fn compile<'a>(rules: impl IntoIterator<Item = &'a ScopeRule>) -> Result<Self, ScopeError> {
        let mut matcher = Matcher::default();

        for rule in rules {
            if !rule.enabled {
                continue;
            }
            let compiled = Compiled {
                host: rule
                    .spec
                    .host
                    .as_ref()
                    .map(|(kind, pattern)| HostMatcher::compile(*kind, pattern))
                    .transpose()?,
                port: rule.spec.port,
                path_prefix: rule.spec.path_prefix.clone(),
            };

            match rule.action {
                Action::Include => matcher.includes.push(compiled),
                Action::Exclude => matcher.excludes.push(compiled),
            }
        }

        Ok(matcher)
    }

    pub fn matches(&self, target: &Target) -> bool {
        if self.excludes.iter().any(|rule| rule.matches(target)) {
            return false;
        }
        // No includes means "everything", which is what an empty scope should do
        // — otherwise a fresh project would show no traffic at all.
        self.includes.is_empty() || self.includes.iter().any(|rule| rule.matches(target))
    }

    /// True when this scope narrows anything. Lets callers skip the filter
    /// entirely rather than walking every flow to no effect.
    pub fn is_unrestricted(&self) -> bool {
        self.includes.is_empty() && self.excludes.is_empty()
    }
}

/// Prefix match on path *segments*, so `/api` covers `/api/v1` but not
/// `/apikeys`. Matching raw string prefixes would silently over-scope.
fn path_has_prefix(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// Backtracking glob: `*` matches any run of characters, `?` exactly one.
///
/// Note `*.linear.app` does **not** match the apex `linear.app` — there is no
/// leading label for `*` to consume before the dot. Scope the apex by adding it
/// explicitly, or use `*linear.app`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    // Where to resume if the current `*` turns out to have consumed too little.
    let (mut star, mut resume) = (None, 0);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last `*` swallow one more character.
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }

    p[pi..].iter().all(|&c| c == '*')
}

fn parse_cidr(spec: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = spec.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((addr, bits))
}

fn ip_in_network(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    fn octets_match(a: &[u8], b: &[u8], bits: u8) -> bool {
        let (whole, rest) = (bits as usize / 8, bits % 8);
        if a[..whole] != b[..whole] {
            return false;
        }
        if rest == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - rest);
        a[whole] & mask == b[whole] & mask
    }

    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => octets_match(&a.octets(), &b.octets(), bits),
        (IpAddr::V6(a), IpAddr::V6(b)) => octets_match(&a.octets(), &b.octets(), bits),
        // Never cross families: a v4 address is not inside a v6 network.
        _ => false,
    }
}

// --- persistence ---

pub fn create_scope(conn: &Connection, name: &str) -> Result<i64, ScopeError> {
    conn.execute("INSERT INTO scope (name) VALUES (?1)", [name])?;
    Ok(conn.last_insert_rowid())
}

pub fn list_scopes(conn: &Connection) -> Result<Vec<Scope>, ScopeError> {
    let mut stmt = conn.prepare("SELECT id, name, is_active FROM scope ORDER BY name")?;
    let rows = stmt.query_map([], |row| {
        Ok(Scope {
            id: row.get(0)?,
            name: row.get(1)?,
            is_active: row.get::<_, i64>(2)? != 0,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Make `id` the active scope. Exactly one scope is active at a time, so this
/// clears the others in the same statement pair.
pub fn set_active(conn: &Connection, id: i64) -> Result<(), ScopeError> {
    conn.execute("UPDATE scope SET is_active = (id = ?1)", [id])?;
    Ok(())
}

pub fn active_scope(conn: &Connection) -> Result<Option<Scope>, ScopeError> {
    let scope = conn
        .query_row(
            "SELECT id, name, is_active FROM scope WHERE is_active != 0 LIMIT 1",
            [],
            |row| {
                Ok(Scope {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    is_active: true,
                })
            },
        )
        .optional()?;
    Ok(scope)
}

/// Add a rule, validating its patterns first so the database can never hold one
/// that fails to compile.
pub fn add_rule(
    conn: &Connection,
    scope_id: i64,
    action: Action,
    spec: &RuleSpec,
    from_node_id: Option<i64>,
) -> Result<i64, ScopeError> {
    if let Some((kind, pattern)) = &spec.host {
        HostMatcher::compile(*kind, pattern)?;
    }

    let (host_kind, host_pattern) = match &spec.host {
        Some((kind, pattern)) => (Some(kind.as_str()), Some(pattern.as_str())),
        None => (None, None),
    };

    conn.execute(
        "INSERT INTO scope_rule
            (scope_id, action, host_kind, host_pattern, port, path_prefix, from_node_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            scope_id,
            action.as_str(),
            host_kind,
            host_pattern,
            spec.port,
            spec.path_prefix,
            from_node_id,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn list_rules(conn: &Connection, scope_id: i64) -> Result<Vec<ScopeRule>, ScopeError> {
    let mut stmt = conn.prepare(
        "SELECT id, action, host_kind, host_pattern, port, path_prefix, enabled, from_node_id
           FROM scope_rule WHERE scope_id = ?1 ORDER BY sort_order, id",
    )?;

    let rows = stmt.query_map([scope_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<u16>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Option<i64>>(7)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (id, action, host_kind, host_pattern, port, path_prefix, enabled, from_node_id) = row?;
        let host = match (host_kind, host_pattern) {
            (Some(kind), Some(pattern)) => Some((HostKind::parse(&kind)?, pattern)),
            _ => None,
        };
        out.push(ScopeRule {
            id,
            action: Action::parse(&action)?,
            spec: RuleSpec {
                host,
                port,
                path_prefix,
            },
            enabled: enabled != 0,
            from_node_id,
        });
    }
    Ok(out)
}

pub fn delete_rule(conn: &Connection, id: i64) -> Result<(), ScopeError> {
    conn.execute("DELETE FROM scope_rule WHERE id = ?1", [id])?;
    Ok(())
}

pub fn load_matcher(conn: &Connection, scope_id: i64) -> Result<Matcher, ScopeError> {
    Matcher::compile(&list_rules(conn, scope_id)?)
}

/// The matcher for whatever scope is active, or an unrestricted one if none is.
pub fn active_matcher(conn: &Connection) -> Result<Matcher, ScopeError> {
    match active_scope(conn)? {
        Some(scope) => load_matcher(conn, scope.id),
        None => Ok(Matcher::default()),
    }
}

// --- sitemap integration ---

/// Turn a sitemap node into a scope rule — the "tick this host/directory to add
/// it to scope" operation.
///
/// A host node scopes the whole host; a directory or leaf scopes that path
/// subtree **on that host only**, which is the conjunction the v1 schema could
/// not express. The rule remembers the node so the UI can render the checkbox
/// state and untick can find it again.
pub fn add_node(
    conn: &Connection,
    scope_id: i64,
    node_id: i64,
    action: Action,
) -> Result<i64, ScopeError> {
    let (kind, host, path): (String, String, String) = conn.query_row(
        "SELECT kind, host, path FROM sitemap_node WHERE id = ?1",
        [node_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    let mut spec = RuleSpec::host(HostKind::Glob, host);
    if kind != "host" {
        spec = spec.with_path_prefix(path);
    }

    add_rule(conn, scope_id, action, &spec, Some(node_id))
}

/// Remove the rules a node contributed. The inverse of `add_node`.
pub fn remove_node(conn: &Connection, scope_id: i64, node_id: i64) -> Result<usize, ScopeError> {
    let n = conn.execute(
        "DELETE FROM scope_rule WHERE scope_id = ?1 AND from_node_id = ?2",
        params![scope_id, node_id],
    )?;
    Ok(n)
}
