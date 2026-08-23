//! Scope matching semantics, and the persistence around them.

use lockgate_core::scope::{self, Action, HostKind, Matcher, RuleSpec, ScopeRule, Target};

fn rule(action: Action, spec: RuleSpec) -> ScopeRule {
    ScopeRule {
        id: 0,
        action,
        spec,
        enabled: true,
        from_node_id: None,
    }
}

fn include(spec: RuleSpec) -> ScopeRule {
    rule(Action::Include, spec)
}

fn exclude(spec: RuleSpec) -> ScopeRule {
    rule(Action::Exclude, spec)
}

fn hit(matcher: &Matcher, url: &str) -> bool {
    // "host:port/path"
    let (authority, path) = url.split_once('/').unwrap_or((url, ""));
    let (host, port) = authority
        .split_once(':')
        .map(|(h, p)| (h, p.parse().unwrap()))
        .unwrap_or((authority, 443));
    let path = format!("/{path}");
    matcher.matches(&Target {
        host,
        port,
        path: &path,
    })
}

#[test]
fn empty_scope_includes_everything() {
    let matcher = Matcher::compile(&[]).unwrap();
    assert!(matcher.is_unrestricted());
    assert!(hit(&matcher, "anything.example.com/x"));
}

#[test]
fn any_include_narrows_to_matching_assets() {
    let rules = vec![include(RuleSpec::host(HostKind::Glob, "*.linear.app"))];
    let matcher = Matcher::compile(&rules).unwrap();

    assert!(hit(&matcher, "api.linear.app/graphql"));
    assert!(hit(&matcher, "a.b.linear.app/x"));
    assert!(!hit(&matcher, "google.com/"));

    // Documented sharp edge: the glob needs a label to consume before the dot,
    // so the apex is NOT covered by "*.linear.app".
    assert!(!hit(&matcher, "linear.app/"));
}

#[test]
fn excludes_beat_includes_regardless_of_order() {
    let spec = RuleSpec::host(HostKind::Glob, "*.linear.app");
    let carve = RuleSpec::host(HostKind::Glob, "cdn.linear.app");

    let forward = Matcher::compile(&[include(spec.clone()), exclude(carve.clone())]).unwrap();
    let reversed = Matcher::compile(&[exclude(carve), include(spec)]).unwrap();

    for matcher in [&forward, &reversed] {
        assert!(hit(matcher, "api.linear.app/x"));
        assert!(!hit(matcher, "cdn.linear.app/x"), "exclude must win");
    }
}

/// The reason for the v2 conjunction rewrite: host AND path, not host OR path.
#[test]
fn constraints_within_a_rule_are_anded() {
    let rules = vec![include(
        RuleSpec::host(HostKind::Glob, "linear.app").with_path_prefix("/api"),
    )];
    let matcher = Matcher::compile(&rules).unwrap();

    assert!(hit(&matcher, "linear.app/api"));
    assert!(hit(&matcher, "linear.app/api/v1/users"));
    // Right host, wrong path.
    assert!(!hit(&matcher, "linear.app/docs"));
    // Right path, wrong host — this is what the old OR-only model got wrong.
    assert!(!hit(&matcher, "evil.com/api"));
}

#[test]
fn path_prefix_respects_segment_boundaries() {
    let rules = vec![include(RuleSpec::default().with_path_prefix("/api"))];
    let matcher = Matcher::compile(&rules).unwrap();

    assert!(hit(&matcher, "x.com/api"));
    assert!(hit(&matcher, "x.com/api/v1"));
    assert!(
        !hit(&matcher, "x.com/apikeys"),
        "/api must not swallow /apikeys"
    );
}

#[test]
fn port_is_resolved_from_scheme_when_absent() {
    let rules = vec![include(
        RuleSpec::host(HostKind::Glob, "localhost").with_port(8080),
    )];
    let matcher = Matcher::compile(&rules).unwrap();

    assert!(hit(&matcher, "localhost:8080/x"));
    assert!(!hit(&matcher, "localhost:3000/x"));
    // No explicit port in the target resolves to 443, not "any".
    assert!(!hit(&matcher, "localhost/x"));
}

#[test]
fn host_matching_is_case_insensitive() {
    let rules = vec![include(RuleSpec::host(HostKind::Glob, "*.Linear.App"))];
    let matcher = Matcher::compile(&rules).unwrap();
    assert!(hit(&matcher, "API.LINEAR.APP/x"));
}

#[test]
fn cidr_matches_ip_literals_only() {
    let rules = vec![include(RuleSpec::host(HostKind::Cidr, "10.0.0.0/8"))];
    let matcher = Matcher::compile(&rules).unwrap();

    assert!(hit(&matcher, "10.1.2.3/x"));
    assert!(!hit(&matcher, "11.1.2.3/x"));
    // A hostname is never inside a network, even if it resolves there.
    assert!(!hit(&matcher, "internal.corp/x"));

    // Non-byte-aligned prefixes must mask correctly.
    let rules = vec![include(RuleSpec::host(HostKind::Cidr, "192.168.1.0/28"))];
    let matcher = Matcher::compile(&rules).unwrap();
    assert!(hit(&matcher, "192.168.1.15/x"));
    assert!(!hit(&matcher, "192.168.1.16/x"));

    // v4 and v6 never cross.
    let rules = vec![include(RuleSpec::host(HostKind::Cidr, "::/0"))];
    let matcher = Matcher::compile(&rules).unwrap();
    assert!(!hit(&matcher, "10.0.0.1/x"));
}

#[test]
fn disabled_rules_are_ignored() {
    let mut disabled = exclude(RuleSpec::host(HostKind::Glob, "cdn.linear.app"));
    disabled.enabled = false;
    let rules = vec![
        include(RuleSpec::host(HostKind::Glob, "*.linear.app")),
        disabled,
    ];

    let matcher = Matcher::compile(&rules).unwrap();
    assert!(
        hit(&matcher, "cdn.linear.app/x"),
        "disabled exclude must not apply"
    );
}

/// A malformed pattern must fail loudly. Silently skipping it would widen scope
/// if the broken rule happened to be an exclude.
#[test]
fn invalid_patterns_are_rejected() {
    assert!(Matcher::compile(&[include(RuleSpec::host(HostKind::Regex, "("))]).is_err());
    assert!(Matcher::compile(&[include(RuleSpec::host(HostKind::Cidr, "10.0.0.0/99"))]).is_err());
    assert!(Matcher::compile(&[include(RuleSpec::host(HostKind::Cidr, "notanip/8"))]).is_err());
}

// --- persistence ---

/// Tests run concurrently, so each needs its own project directory — a shared
/// one races on both the schema and the rows.
fn project_db(name: &str) -> rusqlite::Connection {
    let dir = std::env::temp_dir().join(format!("lockgate-scope-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let paths = lockgate_core::ProjectPaths::new(&dir);
    lockgate_core::db::open_project(&paths).unwrap()
}

#[test]
fn rules_round_trip_through_the_database() {
    let conn = project_db("roundtrip");
    let id = scope::create_scope(&conn, "client assets").unwrap();

    scope::add_rule(
        &conn,
        id,
        Action::Include,
        &RuleSpec::host(HostKind::Glob, "*.linear.app").with_path_prefix("/api"),
        None,
    )
    .unwrap();
    scope::add_rule(
        &conn,
        id,
        Action::Exclude,
        &RuleSpec::host(HostKind::Glob, "cdn.linear.app"),
        None,
    )
    .unwrap();

    let rules = scope::list_rules(&conn, id).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].action, Action::Include);
    assert_eq!(rules[0].spec.path_prefix.as_deref(), Some("/api"));
    assert_eq!(rules[1].action, Action::Exclude);

    let matcher = scope::load_matcher(&conn, id).unwrap();
    assert!(hit(&matcher, "api.linear.app/api/v1"));
    assert!(!hit(&matcher, "cdn.linear.app/api/v1"));
}

/// Validation happens on insert, so the database can never hold a rule that
/// fails to compile later.
#[test]
fn invalid_rules_are_refused_at_insert() {
    let conn = project_db("invalid");
    let id = scope::create_scope(&conn, "s").unwrap();

    assert!(
        scope::add_rule(
            &conn,
            id,
            Action::Include,
            &RuleSpec::host(HostKind::Regex, "(unclosed"),
            None
        )
        .is_err()
    );
    assert!(scope::list_rules(&conn, id).unwrap().is_empty());
}

#[test]
fn exactly_one_scope_is_active() {
    let conn = project_db("active");
    let a = scope::create_scope(&conn, "a").unwrap();
    let b = scope::create_scope(&conn, "b").unwrap();

    assert!(scope::active_scope(&conn).unwrap().is_none());
    // No active scope means unrestricted, not "nothing visible".
    assert!(scope::active_matcher(&conn).unwrap().is_unrestricted());

    scope::set_active(&conn, a).unwrap();
    assert_eq!(scope::active_scope(&conn).unwrap().unwrap().id, a);

    scope::set_active(&conn, b).unwrap();
    assert_eq!(scope::active_scope(&conn).unwrap().unwrap().id, b);
    assert_eq!(
        scope::list_scopes(&conn)
            .unwrap()
            .iter()
            .filter(|s| s.is_active)
            .count(),
        1
    );
}

/// Ticking a sitemap node adds it to scope; unticking removes exactly what it
/// added. A directory node must scope its subtree *on its own host only*.
#[test]
fn sitemap_nodes_convert_to_rules() {
    let conn = project_db("nodes");
    let scope_id = scope::create_scope(&conn, "s").unwrap();

    conn.execute(
        "INSERT INTO sitemap_node (kind, host, path, name, first_seen, last_seen, origin)
         VALUES ('host', 'linear.app', '', 'linear.app', 0, 0, 'observed'),
                ('dir', 'linear.app', '/api', 'api', 0, 0, 'observed')",
        [],
    )
    .unwrap();
    let host_node: i64 = conn
        .query_row("SELECT id FROM sitemap_node WHERE kind = 'host'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let dir_node: i64 = conn
        .query_row("SELECT id FROM sitemap_node WHERE kind = 'dir'", [], |r| {
            r.get(0)
        })
        .unwrap();

    scope::add_node(&conn, scope_id, dir_node, Action::Include).unwrap();
    let matcher = scope::load_matcher(&conn, scope_id).unwrap();
    assert!(hit(&matcher, "linear.app/api/v1"));
    assert!(
        !hit(&matcher, "linear.app/docs"),
        "should scope the subtree only"
    );
    assert!(
        !hit(&matcher, "other.com/api"),
        "should not leak to other hosts"
    );

    // A host node scopes the whole host.
    scope::add_node(&conn, scope_id, host_node, Action::Include).unwrap();
    let matcher = scope::load_matcher(&conn, scope_id).unwrap();
    assert!(hit(&matcher, "linear.app/docs"));

    // Untick: removes only that node's rule.
    let removed = scope::remove_node(&conn, scope_id, host_node).unwrap();
    assert_eq!(removed, 1);
    let matcher = scope::load_matcher(&conn, scope_id).unwrap();
    assert!(!hit(&matcher, "linear.app/docs"));
    assert!(
        hit(&matcher, "linear.app/api/v1"),
        "the dir rule must survive"
    );
}
