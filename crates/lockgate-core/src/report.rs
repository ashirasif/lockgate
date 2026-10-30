//! Report generation: findings and the leads ledger, rendered as one markdown
//! document a hunter can actually submit.
//!
//! The data is already there — findings carry their own prose sections, leads
//! carry verdicts and rulings. This module is the assembly step that hector's
//! roadmap flagged as a manual gap (FINDINGS.md was hand-built); the deliverable
//! of an engagement should not be a copy-paste exercise.
//!
//! Deliberately a pure function of the database. No templates to configure, no
//! LLM in the loop — the narrative prose belongs to whoever filed the finding;
//! the report's job is structure and honest status, not embellishment.

use rusqlite::Connection;

/// Render the whole engagement: findings by severity, then the leads ledger
/// with its verdicts and rulings.
pub fn generate(conn: &Connection) -> rusqlite::Result<String> {
    let findings = crate::finding::list(conn)?;
    let leads = crate::lead::list(conn, None)?;

    let mut out = String::new();
    out.push_str("# Report\n\n");

    // Findings first, worst first — the ordering a triager reads in.
    let order = ["critical", "high", "medium", "low", "info"];
    let mut sorted = findings;
    sorted.sort_by(|a, b| {
        let rank = |s: &str| order.iter().position(|o| *o == s).unwrap_or(order.len());
        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then_with(|| a.id.cmp(&b.id))
    });

    let by_status = |status: &str| sorted.iter().filter(|f| f.status == status).count();
    out.push_str(&format!(
        "{} finding(s): {} open ({} draft, {} confirmed), {} reported, {} false positives.\n\n",
        sorted.len(),
        sorted
            .iter()
            .filter(|f| f.status != "false_positive" && f.status != "wont_fix")
            .count(),
        by_status("draft"),
        by_status("confirmed"),
        by_status("reported"),
        by_status("false_positive"),
    ));

    for f in &sorted {
        out.push_str(&format!(
            "## [{}] {} (`{}`)\n\n",
            f.severity.to_ascii_uppercase(),
            f.title,
            f.status
        ));
        let mut meta = Vec::new();
        if let Some(cwe) = &f.cwe {
            meta.push(format!("CWE {cwe}"));
        }
        if let (Some(vector), Some(score)) = (&f.cvss_vector, f.cvss_score) {
            meta.push(format!("CVSS {score:.1} (`{vector}`)"));
        }
        if let Some(host) = &f.host {
            meta.push(format!("host `{host}`"));
        }
        if !meta.is_empty() {
            out.push_str(&meta.join(" · "));
            out.push_str("\n\n");
        }
        out.push_str(&f.description_md);
        out.push_str("\n\n");
        for (heading, section) in [
            ("Impact", &f.impact_md),
            ("Reproduction", &f.repro_md),
            ("Remediation", &f.remediation_md),
        ] {
            if let Some(text) = section
                && !text.trim().is_empty()
            {
                out.push_str(&format!("### {heading}\n\n{text}\n\n"));
            }
        }
        if !f.evidence.is_empty() {
            out.push_str("### Evidence\n\n");
            for (flow_id, label) in &f.evidence {
                match label {
                    Some(l) => out.push_str(&format!("- flow #{flow_id} — {l}\n")),
                    None => out.push_str(&format!("- flow #{flow_id}\n")),
                }
            }
            out.push('\n');
        }
    }

    // The leads ledger second: it is the engagement's epistemics — what was
    // suspected, what was settled, what was ruled out and why.
    if !leads.is_empty() {
        out.push_str("## Leads\n\n");
        out.push_str("| # | kind | title | status | ruling |\n|---|---|---|---|---|\n");
        for l in &leads {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                l.id,
                l.kind,
                l.title.replace('|', "\\|"),
                l.status,
                l.ruling.as_deref().unwrap_or("—"),
            ));
        }
        out.push('\n');
        for l in leads.iter().filter(|l| l.ruling.is_some()) {
            out.push_str(&format!(
                "**Lead #{}** — verdict: {}; control: {}.\n\nRuling: {} — {}\n\n",
                l.id,
                l.verdict.as_deref().unwrap_or("(none)"),
                l.control.as_deref().unwrap_or("(none)"),
                l.ruling.as_deref().unwrap_or("(none)"),
                l.ruling_reason.as_deref().unwrap_or("(no reason recorded)"),
            ));
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::finding::NewFinding;

    #[test]
    fn renders_findings_in_severity_order_with_leads() {
        let conn = db::open_memory().unwrap();
        conn.execute("INSERT INTO capture_run (id, started_at) VALUES (1, 0)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO flow (id, run_id, source, started_at, method, uri, http_version,
                               req_headers, host, scheme, path, port)
             VALUES (7, 1, 'proxy', 0, 'GET', 'https://x.com/a', 'HTTP/1.1', X'',
                     'x.com', 'https', '/a', 443)",
            [],
        )
        .unwrap();

        crate::finding::insert(
            &conn,
            &NewFinding {
                title: "IDOR on bookings".into(),
                severity: "high".into(),
                status: "confirmed".into(),
                cwe: Some("639".into()),
                description_md: "Sequential ids answer other tenants' data.".into(),
                repro_md: Some("Swap the id; no authz check fires.".into()),
                impact_md: Some("Full cross-tenant read.".into()),
                remediation_md: None,
                host: Some("x.com".into()),
                path: Some("/bookings/{id}".into()),
                cvss_vector: None,
                cvss_score: None,
                cvss_version: None,
                evidence: vec![(7, Some("exploited".into()))],
                origin: "manual".into(),
            },
            1,
        )
        .unwrap();
        crate::finding::insert(
            &conn,
            &NewFinding {
                title: "Server banner".into(),
                severity: "info".into(),
                status: "draft".into(),
                description_md: "Version disclosed.".into(),
                evidence: vec![],
                origin: "manual".into(),
                host: None,
                path: None,
                cwe: None,
                repro_md: None,
                impact_md: None,
                remediation_md: None,
                cvss_vector: None,
                cvss_score: None,
                cvss_version: None,
            },
            2,
        )
        .unwrap();

        crate::lead::propose(
            &conn,
            &crate::lead::NewLead {
                kind: "idor".into(),
                title: "Booking ids".into(),
                rationale_md: "sequential".into(),
                endpoint: None,
                flow_id: None,
            },
            3,
        )
        .unwrap();

        let report = generate(&conn).unwrap();
        let high = report.find("IDOR on bookings").unwrap();
        let info = report.find("Server banner").unwrap();
        assert!(
            high < info,
            "severity orders the document: high must precede info"
        );
        assert!(report.contains("CWE 639"));
        assert!(report.contains("### Reproduction"));
        assert!(report.contains("flow #7 — exploited"), "evidence: {report}");
        assert!(report.contains("## Leads"));
        assert!(report.contains("| proposed |"), "{report}");
    }
}
