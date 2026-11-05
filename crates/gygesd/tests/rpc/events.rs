//! `WatchEvents` against the fake node (docs/interface.md API §4.8): the
//! stream opens with the current state, announces a payment found after it
//! opened (and not the history before), and is refused air-gapped.

use std::time::Duration;

use gyges_proto::v1::{WalletEvent, WatchEventsRequest, wallet_event};

use super::*;

/// The next event, or `None` after `within`.
async fn next(
    events: &mut tonic::Streaming<WalletEvent>,
    within: Duration,
) -> Option<wallet_event::Event> {
    match tokio::time::timeout(within, events.message()).await {
        Ok(Ok(Some(ev))) => ev.event,
        Ok(Ok(None)) => panic!("the stream ended"),
        Ok(Err(e)) => panic!("the stream failed: {e:?}"),
        Err(_) => None,
    }
}

#[tokio::test]
async fn watch_events_opens_with_the_state_and_announces_a_payment() {
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, TEST_CONFIG).await;
    init_key(&mut c, "main").await;
    // History before the stream opens is not announced.
    let receiver = transparent_receiver(&running.state, "main");
    node.mine_with_payments(&[(receiver, 40_000)]);
    wait_spendable(&mut c, "main").await;

    let mut events = c
        .watch_events(WatchEventsRequest::default())
        .await
        .unwrap()
        .into_inner();
    let (mut tip, mut tor, mut sync) = (None, false, false);
    while !(tip.is_some() && tor && sync) {
        match next(&mut events, Duration::from_secs(10)).await {
            Some(wallet_event::Event::Tip(t)) => tip = Some(t.height),
            Some(wallet_event::Event::Tor(_)) => tor = true,
            Some(wallet_event::Event::Sync(s)) => {
                assert_eq!(s.key_id, "main");
                sync = true;
            }
            Some(other) => panic!("only the current state opens the stream: {other:?}"),
            None => panic!("the opening state took too long"),
        }
    }
    assert_eq!(tip, Some(11));

    node.mine_with_payments(&[(receiver, 70_000)]);
    let mut new_tip = None;
    let detected = loop {
        match next(&mut events, Duration::from_secs(30)).await {
            Some(wallet_event::Event::Tip(t)) => new_tip = Some(t.height),
            Some(wallet_event::Event::Detected(d)) => break d,
            Some(wallet_event::Event::Mined(m)) => panic!("not seen unmined first: {m:?}"),
            Some(_) => {}
            None => panic!("the payment was never announced"),
        }
    };
    assert_eq!(new_tip, Some(12), "the new block came first");
    assert_eq!(detected.key_id, "main");
    assert_eq!(detected.net_value, 70_000);
    assert!(detected.mined, "found in a block");
    assert_eq!(detected.txid.len(), 64);

    // Nothing else is announced for the old payment while idle.
    let quiet = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(wallet_event::Event::Detected(d)) =
                next(&mut events, Duration::from_secs(3)).await
            {
                return d;
            }
        }
    })
    .await;
    assert!(quiet.is_err(), "{quiet:?}");

    // One key: an unknown one is refused before the stream opens.
    let err = c
        .watch_events(WatchEventsRequest {
            key_id: "nope".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyNotFound);
    running.task.abort();
}

#[tokio::test]
async fn watch_events_is_refused_air_gapped() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    let err = c
        .watch_events(WatchEventsRequest::default())
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::Airgapped);
    running.task.abort();
}
