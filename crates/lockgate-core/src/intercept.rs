//! Holding traffic in flight so an operator can inspect, edit, or drop it.
//!
//! The proxy handlers call [`Intercept::hold_request`] / [`Intercept::hold_response`]
//! and await a verdict; the TUI polls [`Intercept::queue`] and answers with
//! [`Intercept::forward`] or [`Intercept::drop`]. Nothing here touches the
//! database — a held item is live connection state, not history, and the flow it
//! belongs to was already recorded before the hold began.
//!
//! Every path fails *open*. A dropped reply channel, a cleared queue, or an
//! operator who quits with items still held releases the traffic unmodified
//! rather than wedging the connection: a bug in the frontend must not hang the
//! user's browser.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::oneshot;

use crate::model::{CapturedRequest, CapturedResponse, FlowId, now_micros};

/// Identifies one held item. Distinct from [`FlowId`] because a single flow can
/// be held twice — once on the way out, once on the way back — and the two holds
/// must be answerable independently.
pub type TicketId = u64;

/// The payload of a held item: which direction it was travelling.
#[derive(Clone, Debug)]
pub enum Pending {
    Request(CapturedRequest),
    Response(CapturedResponse),
}

impl Pending {
    pub fn is_request(&self) -> bool {
        matches!(self, Pending::Request(_))
    }
}

/// What the operator decided about a held item.
#[derive(Debug)]
pub enum Verdict {
    /// Let it through, carrying whatever edits were made (or the original).
    Forward(Box<Pending>),
    /// Don't let it through. The handler synthesizes a gateway error in its place
    /// so the client gets a definite answer instead of a hung socket.
    Drop,
}

/// One item waiting on a verdict, as handed to the frontend. Carries the payload
/// by clone so the frontend can render and edit it without holding the queue
/// lock — the authoritative copy stays in the queue until forwarded.
#[derive(Clone, Debug)]
pub struct Held {
    pub ticket: TicketId,
    pub flow_id: FlowId,
    pub pending: Pending,
    /// Unix microseconds, so a view can show how long something has been held.
    pub held_at: i64,
}

/// A queue entry: the public part plus the channel that releases it.
struct Entry {
    held: Held,
    reply: oneshot::Sender<Verdict>,
}

/// The intercept queue. Lives on the [`Engine`](crate::Engine) so the proxy
/// handlers, the TUI, and the MCP all address the same one.
pub struct Intercept {
    /// Checked before anything else on the capture path: when off, holding is a
    /// single relaxed atomic load and traffic flows untouched.
    enabled: AtomicBool,
    /// Which legs to hold. Both on by default, but an exchange holds *twice*
    /// when they are — once out, once back — which is a lot of keystrokes when
    /// you only care about one direction. These make that choice.
    hold_requests: AtomicBool,
    hold_responses: AtomicBool,
    next_ticket: AtomicU64,
    /// `BTreeMap` so `queue()` yields items in the order they were held, which is
    /// the order an operator expects to answer them in.
    queue: Mutex<BTreeMap<TicketId, Entry>>,
}

/// The queue's observable state, compared to decide whether a frontend needs to
/// reload. Opaque by design: only equality is meaningful.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct InterceptRevision {
    tickets: u64,
    queued: usize,
    flags: u8,
}

impl Default for Intercept {
    fn default() -> Self {
        Self {
            // Off: an engine nobody is watching must never hold anything.
            enabled: AtomicBool::new(false),
            // But once switched on, hold both legs — the conservative default is
            // to show the operator everything and let them narrow it.
            hold_requests: AtomicBool::new(true),
            hold_responses: AtomicBool::new(true),
            next_ticket: AtomicU64::new(0),
            queue: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Intercept {
    /// A cheap token that changes whenever anything a frontend displays about
    /// the queue changes, so a UI can skip reloading when it hasn't.
    ///
    /// Derived rather than maintained: there is no `revision` field for a new
    /// mutator to forget to bump. `next_ticket` only ever grows, so pairing it
    /// with the current length distinguishes every case a length alone would
    /// miss — holding one item and answering another in the same interval
    /// leaves the length untouched but always advances the ticket.
    pub fn revision(&self) -> InterceptRevision {
        InterceptRevision {
            tickets: self.next_ticket.load(Ordering::Relaxed),
            queued: self.queue.lock().unwrap().len(),
            flags: (self.enabled.load(Ordering::Relaxed) as u8)
                | ((self.hold_requests.load(Ordering::Relaxed) as u8) << 1)
                | ((self.hold_responses.load(Ordering::Relaxed) as u8) << 2),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn holds_requests(&self) -> bool {
        self.hold_requests.load(Ordering::Relaxed)
    }

    pub fn holds_responses(&self) -> bool {
        self.hold_responses.load(Ordering::Relaxed)
    }

    /// Choose whether requests hold. Turning it off releases any that already
    /// are, for the same reason disabling entirely does.
    pub fn set_hold_requests(&self, on: bool) -> usize {
        self.hold_requests.store(on, Ordering::Relaxed);
        if on {
            0
        } else {
            self.release(|p| p.is_request())
        }
    }

    /// Choose whether responses hold.
    pub fn set_hold_responses(&self, on: bool) -> usize {
        self.hold_responses.store(on, Ordering::Relaxed);
        if on {
            0
        } else {
            self.release(|p| !p.is_request())
        }
    }

    /// Turn interception on or off.
    ///
    /// Switching *off* releases everything currently held, unmodified. The
    /// alternative — leaving items stranded in a queue no longer being watched —
    /// hangs connections the operator has already decided they don't care about.
    /// Returns the number of items released.
    pub fn set_enabled(&self, on: bool) -> usize {
        self.enabled.store(on, Ordering::Relaxed);
        if on { 0 } else { self.forward_all() }
    }

    /// Hold a request until answered. Returns the verdict; forwards immediately
    /// if interception is off.
    pub async fn hold_request(&self, flow_id: FlowId, req: CapturedRequest) -> Verdict {
        self.hold(flow_id, Pending::Request(req)).await
    }

    /// Hold a response until answered. Returns the verdict; forwards immediately
    /// if interception is off.
    pub async fn hold_response(&self, flow_id: FlowId, res: CapturedResponse) -> Verdict {
        self.hold(flow_id, Pending::Response(res)).await
    }

    async fn hold(&self, flow_id: FlowId, pending: Pending) -> Verdict {
        let wanted = if pending.is_request() {
            self.holds_requests()
        } else {
            self.holds_responses()
        };
        if !self.is_enabled() || !wanted {
            return Verdict::Forward(Box::new(pending));
        }

        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        let (reply, rx) = oneshot::channel();
        let held = Held {
            ticket,
            flow_id,
            pending: pending.clone(),
            held_at: now_micros(),
        };
        self.queue
            .lock()
            .unwrap()
            .insert(ticket, Entry { held, reply });

        // A closed channel means the entry was dropped without an answer. Fail
        // open: release the original rather than hanging the connection.
        rx.await
            .unwrap_or_else(|_| Verdict::Forward(Box::new(pending)))
    }

    // --- frontend verbs ---

    /// Everything currently held, oldest first.
    pub fn queue(&self) -> Vec<Held> {
        self.queue
            .lock()
            .unwrap()
            .values()
            .map(|e| e.held.clone())
            .collect()
    }

    /// How many items are held. Cheaper than building the whole queue for a
    /// badge in a status bar.
    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One held item by ticket, or `None` if it is no longer held.
    pub fn get(&self, ticket: TicketId) -> Option<Held> {
        self.queue
            .lock()
            .unwrap()
            .get(&ticket)
            .map(|e| e.held.clone())
    }

    /// Release one item, optionally replacing its payload with an edited one.
    /// `false` if the ticket is unknown (already answered, or never existed).
    pub fn forward(&self, ticket: TicketId, edited: Option<Pending>) -> bool {
        let Some(entry) = self.queue.lock().unwrap().remove(&ticket) else {
            return false;
        };
        let payload = edited.unwrap_or(entry.held.pending);
        // The receiver is gone only if the connection died while held; the item
        // is off the queue either way, so this is still a successful answer.
        let _ = entry.reply.send(Verdict::Forward(Box::new(payload)));
        true
    }

    /// Everything currently held on one leg, oldest first. The two legs are
    /// answered independently, so the frontend lists them independently.
    pub fn queue_of(&self, requests: bool) -> Vec<Held> {
        self.queue
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.held.pending.is_request() == requests)
            .map(|e| e.held.clone())
            .collect()
    }

    /// Forward every held item matching `wanted`, unmodified.
    fn release(&self, wanted: impl Fn(&Pending) -> bool) -> usize {
        let drained: Vec<Entry> = {
            let mut queue = self.queue.lock().unwrap();
            let tickets: Vec<TicketId> = queue
                .iter()
                .filter(|(_, e)| wanted(&e.held.pending))
                .map(|(t, _)| *t)
                .collect();
            tickets
                .into_iter()
                .filter_map(|t| queue.remove(&t))
                .collect()
        };
        let n = drained.len();
        for entry in drained {
            let _ = entry
                .reply
                .send(Verdict::Forward(Box::new(entry.held.pending)));
        }
        n
    }

    /// Release everything held, unmodified. Returns how many were released.
    pub fn forward_all(&self) -> usize {
        // Drain under the lock, answer outside it: `send` on a oneshot never
        // blocks, but keeping the critical section to the map operation means a
        // large queue can't stall a handler trying to hold a new item.
        let drained: Vec<Entry> = std::mem::take(&mut *self.queue.lock().unwrap())
            .into_values()
            .collect();
        let n = drained.len();
        for entry in drained {
            let _ = entry
                .reply
                .send(Verdict::Forward(Box::new(entry.held.pending)));
        }
        n
    }

    /// Drop one held item. `false` if the ticket is unknown.
    ///
    /// Named `discard` rather than `drop`: an inherent `drop` method shadows
    /// `Drop::drop` and makes every call site a compile error. The operator-facing
    /// verb is still "drop".
    pub fn discard(&self, ticket: TicketId) -> bool {
        let Some(entry) = self.queue.lock().unwrap().remove(&ticket) else {
            return false;
        };
        let _ = entry.reply.send(Verdict::Drop);
        true
    }

    /// Drop everything held. Returns how many were dropped.
    pub fn discard_all(&self) -> usize {
        let drained: Vec<Entry> = std::mem::take(&mut *self.queue.lock().unwrap())
            .into_values()
            .collect();
        let n = drained.len();
        for entry in drained {
            let _ = entry.reply.send(Verdict::Drop);
        }
        n
    }
}
