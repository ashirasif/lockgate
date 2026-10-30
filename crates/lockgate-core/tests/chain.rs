//! The chain pass on the engine: every path that lands "something new" —
//! `create_finding`, `create_lead`, a lead settling as verified — runs the
//! playbook against what is already held, in both directions. Retrospective:
//! complete pairs become chain leads. Optimistic: an unpaired basis gets its
//! questions filed as leads parented to a basis chain, ready to hand to
//! whoever does the looking.

use lockgate_core::{Engine, NewFinding};

fn finding(cwe: &str, host: &str) -> NewFinding {
    NewFinding {
        title: "t".into(),
        severity: "medium".into(),
        status: "confirmed".into(),
        cwe: Some(cwe.into()),
        description_md: "d".into(),
        host: Some(host.into()),
        ..NewFinding::default()
    }
}

fn chains(engine: &Engine) -> Vec<String> {
    engine
        .leads(None)
        .iter()
        .filter(|l| l.kind == "chain")
        .map(|l| l.title.clone())
        .collect()
}

#[tokio::test]
async fn a_complete_pair_files_a_chain_lead() {
    let engine = Engine::new();

    // First leg: an XSS lands on an empty ledger — no pair, but the basis
    // chain asks the questions that would complete its patterns.
    engine.create_finding(finding("79", "t.com")).await.unwrap();
    let titles = chains(&engine);
    assert_eq!(
        titles,
        vec!["chain[basis] f#1 (xss)".to_string()],
        "{titles:?}"
    );
    let questions: Vec<String> = engine
        .leads(None)
        .iter()
        .filter(|l| l.chain_id.is_some())
        .map(|l| l.title.clone())
        .collect();
    assert_eq!(
        questions.len(),
        2,
        "session readability and CSP: {questions:?}"
    );

    // Second leg: the session cookie is JavaScript-readable. The playbook
    // sees account takeover where the rows were filed as medium and low.
    engine
        .create_finding(finding("1004", "t.com"))
        .await
        .unwrap();
    let titles = chains(&engine);
    assert!(titles.contains(&"chain[xss-js-readable-session] f#1 + f#2".to_string()));
    assert_eq!(titles.len(), 2, "the basis chain stays, the pair lands");

    let chain = engine
        .leads(None)
        .into_iter()
        .find(|l| l.title.contains("f#1 + f#2"))
        .unwrap();
    assert_eq!(chain.status, "proposed");
    assert!(chain.rationale_md.contains("account takeover"));
}

#[tokio::test]
async fn a_false_positive_never_composes() {
    let engine = Engine::new();
    let mut f = finding("79", "t.com");
    f.status = "false_positive".into();
    engine.create_finding(f).await.unwrap();
    engine
        .create_finding(finding("1004", "t.com"))
        .await
        .unwrap();

    // No pair with the walked-back finding, and it is nobody's basis: the
    // only chain is the session finding asking for an XSS.
    let titles = chains(&engine);
    assert_eq!(
        titles,
        vec!["chain[basis] f#2 (js-readable-session)".to_string()],
        "{titles:?}"
    );
}

#[tokio::test]
async fn a_lead_composes_and_verification_does_not_double_file() {
    let engine = Engine::new();
    engine
        .create_finding(finding("942", "t.com"))
        .await
        .unwrap();

    // The IDOR lead completes the CORS pattern on arrival... (its id is 3:
    // the CORS finding's basis chain took 2.)
    engine
        .create_lead(&lockgate_core::NewLead {
            kind: "idor".into(),
            title: "Booking ids are sequential".into(),
            rationale_md: "GET /bookings/4711 returned another tenant's data".into(),
            endpoint: Some("https://t.com/bookings/{id}".into()),
            flow_id: None,
            chain_id: None,
        })
        .unwrap();
    assert!(
        chains(&engine).contains(&"chain[cors-cred-idor] f#1 + l#3".to_string()),
        "{:?}",
        chains(&engine)
    );

    // ...and settling it as verified re-runs the pass, which dedups: three
    // chains — two bases and the pair — before the verdict, three after.
    let before = chains(&engine).len();
    engine
        .record_lead_verdict(
            3,
            "verified",
            Some("200 with tenant B's id; 403 as tenant A"),
            Some("same request, swapped tenant: 200 vs 403"),
        )
        .unwrap();
    assert_eq!(
        chains(&engine).len(),
        before,
        "the verified re-trigger recognises what it already proposed"
    );
}

#[tokio::test]
async fn the_model_pass_files_and_reads_back_a_chain() {
    let engine = Engine::new();
    engine.create_finding(finding("79", "t.com")).await.unwrap();

    // A composition no table knows: the model pass files it directly, with
    // its own question to dispatch.
    let filed = engine
        .file_chain(lockgate_core::chain::NewChain {
            title: "chain[xss-password-reuse] f#1".into(),
            rationale_md: "Reflected XSS on the login page: anything harvested \
                           phishes the reused password."
                .into(),
            endpoint: Some("t.com".into()),
            members: vec![lockgate_core::chain::Member {
                kind: "finding".into(),
                id: 1,
            }],
            questions: vec![lockgate_core::chain::ChainQuestion {
                kind: "logic".into(),
                title: "Does the login rate limit survive a password rotation?".into(),
                rationale_md: "If not, harvested credentials stay brute-forceable.".into(),
            }],
        })
        .unwrap();
    assert!(filed.created);

    // get_chain reassembles it: the member and the parented question.
    let full = engine.chain(filed.id).unwrap();
    assert_eq!(full.title, "chain[xss-password-reuse] f#1");
    assert_eq!(full.members.len(), 1);
    assert_eq!(full.questions.len(), 1);
    assert_eq!(full.questions[0].chain_id, Some(filed.id));

    // The review brief carries everything for the next model pass.
    let review = engine.chain_review().unwrap();
    assert!(review.playbook.len() >= 5);
    assert!(review.findings.iter().any(|f| f.primitive == Some("xss")));
    assert!(review.chains.iter().any(|c| c.id == filed.id));
}
