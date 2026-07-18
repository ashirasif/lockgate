use std::sync::Mutex;

use crate::model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary};

/// The flow history. The `Mutex` is private: every method locks, does one small
/// synchronous thing, and unlocks. No guard ever escapes, so it's impossible to
/// accidentally hold the lock across an `.await`.
#[derive(Default)]
pub struct FlowStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    flows: Vec<Flow>,
    next_id: FlowId,
}

impl FlowStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resume id allocation from `next_id` — used when reopening a database so
    /// fresh flows do not collide with the ones already stored.
    pub fn with_next_id(next_id: FlowId) -> Self {
        Self {
            inner: Mutex::new(Inner {
                flows: Vec::new(),
                next_id,
            }),
        }
    }

    /// Record an outgoing request, returning its new id.
    pub fn add_request(&self, request: CapturedRequest, started_at: i64) -> FlowId {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_id;
        inner.next_id += 1;
        inner.flows.push(Flow {
            id,
            request,
            response: None,
            started_at,
            ended_at: None,
        });
        id
    }

    /// Attach a response to a previously recorded request. No-op if the id is gone.
    pub fn attach_response(&self, id: FlowId, response: CapturedResponse, ended_at: i64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(flow) = inner.flows.iter_mut().find(|f| f.id == id) {
            flow.response = Some(response);
            flow.ended_at = Some(ended_at);
        }
    }

    /// Clone a full flow out from under the lock (so callers can await afterwards).
    pub fn get(&self, id: FlowId) -> Option<Flow> {
        let inner = self.inner.lock().unwrap();
        inner.flows.iter().find(|f| f.id == id).cloned()
    }

    /// Lightweight rows for list views.
    pub fn list(&self) -> Vec<FlowSummary> {
        let inner = self.inner.lock().unwrap();
        inner
            .flows
            .iter()
            .map(|f| FlowSummary {
                id: f.id,
                method: f.request.method.clone(),
                uri: f.request.uri.clone(),
                status: f.response.as_ref().map(|r| r.status),
            })
            .collect()
    }
}
