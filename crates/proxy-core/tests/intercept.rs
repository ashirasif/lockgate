//! The intercept queue: holding traffic, answering it, and the fail-open
//! guarantees that keep a frontend bug from wedging a connection.

use std::sync::Arc;
use std::time::Duration;

use hudsucker::hyper::{HeaderMap, Method, StatusCode, Uri, Version, body::Bytes};
use proxy_core::{CapturedRequest, CapturedResponse, Intercept, Pending, Verdict};

fn request(uri: &str) -> CapturedRequest {
    CapturedRequest {
        method: Method::GET,
        uri: uri.parse::<Uri>().unwrap(),
        version: Version::HTTP_11,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    }
}

fn response(status: u16) -> CapturedResponse {
    CapturedResponse {
        status: StatusCode::from_u16(status).unwrap(),
        version: Version::HTTP_11,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    }
}

/// Spin until the queue reaches `n`, so a test never races the held task.
async fn wait_for_queue(intercept: &Intercept, n: usize) {
    for _ in 0..200 {
        if intercept.len() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("queue never reached {n} (stuck at {})", intercept.len());
}

#[tokio::test]
async fn disabled_passes_through_without_queueing() {
    let intercept = Intercept::default();
    let verdict = intercept.hold_request(1, request("http://a/x")).await;
    assert!(matches!(verdict, Verdict::Forward(_)));
    assert!(intercept.is_empty(), "nothing should queue while disabled");
}

#[tokio::test]
async fn forward_releases_the_original() {
    let intercept = Arc::new(Intercept::default());
    intercept.set_enabled(true);

    let held = tokio::spawn({
        let intercept = Arc::clone(&intercept);
        async move { intercept.hold_request(7, request("http://a/x")).await }
    });

    wait_for_queue(&intercept, 1).await;
    let item = intercept.queue().remove(0);
    assert_eq!(item.flow_id, 7);
    assert!(intercept.forward(item.ticket, None));

    match held.await.unwrap() {
        Verdict::Forward(p) => match *p {
            Pending::Request(r) => assert_eq!(r.uri.to_string(), "http://a/x"),
            Pending::Response(_) => panic!("a request hold returned a response"),
        },
        Verdict::Drop => panic!("expected forward"),
    }
    assert!(intercept.is_empty());
}

#[tokio::test]
async fn forward_can_substitute_an_edited_request() {
    let intercept = Arc::new(Intercept::default());
    intercept.set_enabled(true);

    let held = tokio::spawn({
        let intercept = Arc::clone(&intercept);
        async move {
            intercept
                .hold_request(1, request("http://a/original"))
                .await
        }
    });

    wait_for_queue(&intercept, 1).await;
    let ticket = intercept.queue()[0].ticket;
    let edited = Pending::Request(request("http://a/edited"));
    assert!(intercept.forward(ticket, Some(edited)));

    match held.await.unwrap() {
        Verdict::Forward(p) => match *p {
            Pending::Request(r) => assert_eq!(r.uri.to_string(), "http://a/edited"),
            Pending::Response(_) => panic!("a request hold returned a response"),
        },
        Verdict::Drop => panic!("expected forward"),
    }
}

#[tokio::test]
async fn drop_answers_with_drop() {
    let intercept = Arc::new(Intercept::default());
    intercept.set_enabled(true);

    let held = tokio::spawn({
        let intercept = Arc::clone(&intercept);
        async move { intercept.hold_response(3, response(200)).await }
    });

    wait_for_queue(&intercept, 1).await;
    let ticket = intercept.queue()[0].ticket;
    assert!(intercept.discard(ticket));
    assert!(matches!(held.await.unwrap(), Verdict::Drop));
}

/// A request and its response are two independent holds on one flow, and each
/// must be answerable on its own.
#[tokio::test]
async fn both_directions_of_one_flow_hold_independently() {
    let intercept = Arc::new(Intercept::default());
    intercept.set_enabled(true);

    let req_hold = tokio::spawn({
        let intercept = Arc::clone(&intercept);
        async move { intercept.hold_request(9, request("http://a/x")).await }
    });
    wait_for_queue(&intercept, 1).await;
    let res_hold = tokio::spawn({
        let intercept = Arc::clone(&intercept);
        async move { intercept.hold_response(9, response(404)).await }
    });
    wait_for_queue(&intercept, 2).await;

    let queue = intercept.queue();
    assert!(queue.iter().all(|h| h.flow_id == 9));
    assert_ne!(queue[0].ticket, queue[1].ticket, "one ticket per direction");
    assert!(queue[0].pending.is_request());
    assert!(!queue[1].pending.is_request());

    // Answer them differently to prove they are not coupled.
    assert!(intercept.discard(queue[0].ticket));
    assert!(intercept.forward(queue[1].ticket, None));
    assert!(matches!(req_hold.await.unwrap(), Verdict::Drop));
    assert!(matches!(res_hold.await.unwrap(), Verdict::Forward(_)));
}

#[tokio::test]
async fn forward_all_releases_everything() {
    let intercept = Arc::new(Intercept::default());
    intercept.set_enabled(true);

    let holds: Vec<_> = (0..5)
        .map(|i| {
            let intercept = Arc::clone(&intercept);
            tokio::spawn(async move { intercept.hold_request(i, request("http://a/x")).await })
        })
        .collect();

    wait_for_queue(&intercept, 5).await;
    assert_eq!(intercept.forward_all(), 5);
    for h in holds {
        assert!(matches!(h.await.unwrap(), Verdict::Forward(_)));
    }
    assert!(intercept.is_empty());
}

/// Switching interception off must not strand traffic in a queue nobody is
/// watching — everything held is released unmodified.
#[tokio::test]
async fn disabling_releases_held_traffic() {
    let intercept = Arc::new(Intercept::default());
    intercept.set_enabled(true);

    let held = tokio::spawn({
        let intercept = Arc::clone(&intercept);
        async move { intercept.hold_request(1, request("http://a/x")).await }
    });
    wait_for_queue(&intercept, 1).await;

    assert_eq!(
        intercept.set_enabled(false),
        1,
        "should release the held item"
    );
    assert!(matches!(held.await.unwrap(), Verdict::Forward(_)));
    assert!(intercept.is_empty());
}

#[tokio::test]
async fn answering_an_unknown_ticket_is_a_no_op() {
    let intercept = Intercept::default();
    intercept.set_enabled(true);
    assert!(!intercept.forward(999, None));
    assert!(!intercept.discard(999));
}
