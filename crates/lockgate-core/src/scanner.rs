//! The passive scanner: rules over responses, filed as draft findings.
//!
//! Always-on, cheap, and honest about what it is: header-level observations
//! that are *worth a look*, not verdicts. Every finding it files carries
//! `origin: "workflow"` — "the tool thinks", as the schema comment puts it —
//! and `status: "draft"`, so nothing it says can masquerade as verified work.
//! Deduplication is per (rule, host): one banner finding per host, not one per
//! response, or a crawl would drown the triage window.
//!
//! The rules are deliberately few and deliberately header-shaped. Anything
//! smarter (reflected-parameter probes, authz diffs) is the *agents'* job —
//! they file findings with evidence and controls; the scanner just never
//! sleeps.

use hudsucker::hyper::HeaderMap;

/// One rule match. `rule` is the stable dedup key's other half (the host is
/// the first).
#[derive(Clone, Debug)]
pub struct ScanHit {
    pub rule: &'static str,
    pub severity: &'static str,
    pub cwe: Option<&'static str>,
    pub title: String,
    pub description_md: String,
}

/// What a run over recent history filed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanOutcome {
    pub scanned: usize,
    pub filed: usize,
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn is_html(mime: &Option<String>) -> bool {
    mime.as_deref().is_some_and(|m| m.starts_with("text/html"))
}

fn cookies_without(headers: &HeaderMap, flag: &str) -> Vec<String> {
    let mut names = Vec::new();
    for value in headers.get_all("set-cookie") {
        let Ok(value) = value.to_str() else { continue };
        let Some(name) = value.split(';').next().and_then(|p| p.split('=').next()) else {
            continue;
        };
        let name = name.trim();
        let has_flag = value
            .split(';')
            .skip(1)
            .any(|a| a.trim().eq_ignore_ascii_case(flag));
        if !name.is_empty() && !has_flag {
            names.push(name.to_string());
        }
    }
    names
}

/// The rules, run over one exchange. Pure: no database, no engine, so tests
/// and the on-demand scan and the capture hook all share one truth.
pub fn scan(scheme: &str, mime: &Option<String>, resp_headers: &HeaderMap) -> Vec<ScanHit> {
    let mut hits = Vec::new();
    let https = scheme == "https";

    // CORS: wildcard origin with credentials is not a hardening nit, it is a
    // bug — any origin can read credentialed responses.
    let acao = header(resp_headers, "access-control-allow-origin");
    let acac = header(resp_headers, "access-control-allow-credentials");
    if acao.is_some_and(|v| v.trim() == "*") && acac.is_some_and(|v| v.trim() == "true") {
        hits.push(ScanHit {
            rule: "cors_wildcard_credentials",
            severity: "medium",
            cwe: Some("942"),
            title: "CORS allows any origin with credentials".into(),
            description_md: "The response carries `Access-Control-Allow-Origin: *` together \
                 with `Access-Control-Allow-Credentials: true`. A wildcard origin cannot be \
                 combined with credentials safely: any site the victim visits can read the \
                 response with their cookies attached."
                .into(),
        });
    }

    // Cookie flags, on the session cookies a pentest actually cares about.
    let unsecured = cookies_without(resp_headers, "secure");
    if https && !unsecured.is_empty() {
        hits.push(ScanHit {
            rule: "cookie_missing_secure",
            severity: "low",
            cwe: Some("614"),
            title: format!("Cookie(s) set without Secure: {}", unsecured.join(", ")),
            description_md: format!(
                "Set-Cookie for {} lacks the `Secure` flag over HTTPS, so the cookie will \
                 also travel on any plain-HTTP request to this host.",
                unsecured.join(", ")
            ),
        });
    }
    let no_httponly = cookies_without(resp_headers, "httponly");
    if !no_httponly.is_empty() {
        hits.push(ScanHit {
            rule: "cookie_missing_httponly",
            severity: "low",
            cwe: Some("1004"),
            title: format!("Cookie(s) set without HttpOnly: {}", no_httponly.join(", ")),
            description_md: format!(
                "Set-Cookie for {} lacks `HttpOnly`, so the cookie is readable from \
                 JavaScript — one XSS away from theft.",
                no_httponly.join(", ")
            ),
        });
    }

    // HSTS: only meaningful on https, and only worth a line, not a finding
    // war — one per host via dedup.
    if https && header(resp_headers, "strict-transport-security").is_none() {
        hits.push(ScanHit {
            rule: "missing_hsts",
            severity: "low",
            cwe: Some("319"),
            title: "No Strict-Transport-Security header".into(),
            description_md: "The HTTPS response sets no HSTS policy, so a man-in-the-middle \
                 can strip TLS on the first request of a session."
                .into(),
        });
    }

    // CSP on HTML: information-grade at draft, because a page can be fine
    // without it — but its absence is worth seeing while triaging XSS.
    if is_html(mime) && header(resp_headers, "content-security-policy").is_none() {
        hits.push(ScanHit {
            rule: "missing_csp",
            severity: "info",
            cwe: Some("1021"),
            title: "HTML served without a Content-Security-Policy".into(),
            description_md: "The HTML response carries no CSP. Absence is not a bug by \
                 itself; it is the background condition that makes stored/reflected XSS \
                 land. Check where this page reflects input."
                .into(),
        });
    }

    // Version disclosure: info. Useful for pinning exploits, not a defect.
    let banner = header(resp_headers, "server")
        .or_else(|| header(resp_headers, "x-powered-by"))
        .unwrap_or_default();
    let discloses_version = banner.split('/').count() > 1;
    if discloses_version {
        hits.push(ScanHit {
            rule: "server_disclosure",
            severity: "info",
            cwe: Some("200"),
            title: format!("Server banner discloses a version: {}", banner.trim()),
            description_md: format!(
                "`{}` advertises a specific version. Not a defect — useful when the \
                 program's stack has a known CVE.",
                banner.trim()
            ),
        });
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use hudsucker::hyper::header::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            // append, not insert: repeated Set-Cookie lines are the normal
            // shape, and insert would keep only the last.
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn hit<'a>(hits: &'a [ScanHit], rule: &str) -> &'a ScanHit {
        hits.iter().find(|h| h.rule == rule).unwrap_or_else(|| {
            panic!(
                "expected rule {rule}, got {:?}",
                hits.iter().map(|h| h.rule).collect::<Vec<_>>()
            )
        })
    }

    #[test]
    fn cors_wildcard_with_credentials_is_the_real_bug() {
        let h = headers(&[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
        ]);
        let hits = scan("https", &None, &h);
        assert_eq!(hit(&hits, "cors_wildcard_credentials").severity, "medium");

        // Either half missing, and it is not the bug (an https response
        // without HSTS still raises its own rule, so assert on CORS only).
        let h = headers(&[("access-control-allow-origin", "*")]);
        assert!(
            scan("https", &None, &h)
                .iter()
                .all(|h| h.rule != "cors_wildcard_credentials")
        );
        let h = headers(&[
            ("access-control-allow-origin", "https://app.target.com"),
            ("access-control-allow-credentials", "true"),
        ]);
        assert!(
            scan("https", &None, &h)
                .iter()
                .all(|h| h.rule != "cors_wildcard_credentials")
        );
    }

    #[test]
    fn cookie_flag_rules_name_the_cookies() {
        let h = headers(&[
            ("set-cookie", "sid=abc; Path=/"),
            ("set-cookie", "pref=dark; Secure; HttpOnly"),
        ]);
        let hits = scan("https", &None, &h);
        assert!(
            hit(&hits, "cookie_missing_secure").title.contains("sid"),
            "pref has Secure; sid does not"
        );
        assert!(
            hit(&hits, "cookie_missing_httponly").title.contains("sid"),
            "pref has HttpOnly; sid does not"
        );

        // No Secure warning on plain http — the flag means nothing there.
        let hits = scan("http", &None, &h);
        assert!(hits.iter().all(|h| h.rule != "cookie_missing_secure"));
    }

    #[test]
    fn hsts_csp_and_banner_only_when_they_apply() {
        let h = headers(&[("server", "nginx/1.24.0")]);
        let html = Some("text/html".to_string());
        let hits = scan("https", &html, &h);
        hit(&hits, "missing_hsts");
        hit(&hits, "missing_csp");
        assert!(hit(&hits, "server_disclosure").title.contains("1.24.0"));

        // Plain http: no HSTS rule (it is an https control). JSON: no CSP rule.
        let hits = scan("http", &None, &h);
        assert!(hits.iter().all(|h| h.rule != "missing_hsts"));
        assert!(hits.iter().all(|h| h.rule != "missing_csp"));
        let json = Some("application/json".to_string());
        let hits = scan("https", &json, &h);
        assert!(hits.iter().all(|h| h.rule != "missing_csp"));
    }

    #[test]
    fn a_clean_response_raises_nothing() {
        let h = headers(&[
            ("strict-transport-security", "max-age=63072000"),
            ("content-security-policy", "default-src 'self'"),
            ("set-cookie", "sid=abc; Secure; HttpOnly; Path=/"),
        ]);
        let html = Some("text/html".to_string());
        assert!(scan("https", &html, &h).is_empty());
    }
}
