//! Push notifications: the run's headline events, delivered where the operator
//! is — which, during an autonomous run, is often not at the keyboard.
//!
//! Speaks the ntfy.sh shape (POST a body, title in a header), because it needs
//! no account, no app store, and works on any phone that can install nothing
//! but a topic URL. The engine hands events to a channel and forgets them:
//! notification delivery must never slow capture, and a failed push is a
//! missed headline, not a lost finding — the evidence is in the database.

use tokio::sync::mpsc;

/// What is worth a buzz on the operator's phone.
#[derive(Clone, Debug)]
pub enum Event {
    /// A finding was filed — by the scanner or by an agent.
    Finding {
        severity: String,
        title: String,
        host: Option<String>,
    },
    /// A lead changed state, so the run's story moved: verified, refuted,
    /// reported.
    LeadSettled {
        lead_id: i64,
        title: String,
        status: String,
    },
}

impl Event {
    /// (title, body) for the push payload.
    pub fn headline(&self) -> (String, String) {
        match self {
            Event::Finding {
                severity,
                title,
                host,
            } => (
                format!("lockgate: {severity} finding"),
                match host {
                    Some(host) => format!("{title} — {host}"),
                    None => title.clone(),
                },
            ),
            Event::LeadSettled {
                lead_id,
                title,
                status,
            } => (
                format!("lockgate: lead {status}"),
                format!("#{lead_id} {title}"),
            ),
        }
    }
}

/// A fire-and-forget handle. Cheap to clone; `None` when notifications are off,
/// so the engine never branches on configuration.
#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::UnboundedSender<Event>,
}

impl Notifier {
    /// Spawn the delivery task for an ntfy-compatible topic URL
    /// (e.g. `https://ntfy.sh/my-secret-topic`). Treat the topic as a secret:
    /// anyone who has it can read the run's headlines.
    pub fn spawn(url: String) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            while let Some(event) = rx.recv().await {
                let (title, body) = event.headline();
                let result = client
                    .post(&url)
                    .header("X-Title", &title)
                    .header("X-Priority", "default")
                    .timeout(std::time::Duration::from_secs(10))
                    .body(body)
                    .send()
                    .await;
                if let Err(e) = result {
                    tracing::warn!(error = %e, "notification failed");
                }
            }
        });
        Self { tx }
    }

    /// A no-op handle for tests and for engines that run without
    /// notifications.
    pub fn disabled() -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        Self { tx }
    }

    /// Queue an event. Never blocks, never fails the caller: a full or closed
    /// channel means the push is lost, which is the correct worst case.
    pub fn notify(&self, event: Event) {
        let _ = self.tx.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headlines_read_like_headlines() {
        let (title, body) = Event::Finding {
            severity: "high".into(),
            title: "IDOR on bookings".into(),
            host: Some("target.com".into()),
        }
        .headline();
        assert_eq!(title, "lockgate: high finding");
        assert_eq!(body, "IDOR on bookings — target.com");

        let (title, body) = Event::LeadSettled {
            lead_id: 7,
            title: "Rate limit on /login".into(),
            status: "verified".into(),
        }
        .headline();
        assert_eq!(title, "lockgate: lead verified");
        assert_eq!(body, "#7 Rate limit on /login");
    }

    #[tokio::test]
    async fn notify_never_fails_the_caller() {
        let n = Notifier::disabled();
        n.notify(Event::Finding {
            severity: "info".into(),
            title: "x".into(),
            host: None,
        });
        // Disabled handle: the receiver was dropped, and this must not panic.
    }
}
