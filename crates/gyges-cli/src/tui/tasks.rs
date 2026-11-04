//! One-shot RPCs the state asks for, each on a short-lived connection of its
//! own, answered with an [`Event`].
//!
//! A connection per request keeps them off the poller's reading connection
//! (which never unlocks) and lets them run while the poller waits. Over the
//! Unix socket a connection and handshake cost a millisecond or two.

use std::future::Future;

use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{GetCurrentAddressRequest, NewAddressRequest};
use tokio::sync::mpsc;
use tonic::transport::Channel;

use crate::client::Ctx;
use crate::exit::CliError;

use super::addresses::AddrView;
use super::app::Event;

/// Connect, run `call`, and send what `answer` makes of the result.
pub fn spawn<T, F, Fut>(
    ctx: &Ctx,
    tx: &mpsc::UnboundedSender<Event>,
    call: F,
    answer: impl FnOnce(Result<T, String>) -> Event + Send + 'static,
) where
    T: Send + 'static,
    F: FnOnce(GygesClient<Channel>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, tonic::Status>> + Send,
{
    let ctx = ctx.clone();
    let tx = tx.clone();
    tokio::spawn(async move {
        let result = match ctx.connect().await {
            Ok(conn) => call(conn.client)
                .await
                .map_err(|s| CliError::from_status(s).message()),
            Err(e) => Err(e.message()),
        };
        let _ = tx.send(answer(result));
    });
}

pub fn load_address(ctx: &Ctx, tx: &mpsc::UnboundedSender<Event>, key_id: String, view: AddrView) {
    let req = GetCurrentAddressRequest {
        key_id: key_id.clone(),
        pool: view.pool() as i32,
    };
    spawn(
        ctx,
        tx,
        move |mut c| async move { c.get_current_address(req).await.map(|r| r.into_inner()) },
        move |result| Event::Address {
            key_id,
            view,
            result,
        },
    );
}

pub fn new_address(ctx: &Ctx, tx: &mpsc::UnboundedSender<Event>, key_id: String, label: String) {
    let req = NewAddressRequest {
        key_id: key_id.clone(),
        receivers: Vec::new(),
        label,
    };
    spawn(
        ctx,
        tx,
        move |mut c| async move { c.new_address(req).await.map(|r| r.into_inner()) },
        move |result| Event::AddressMade { key_id, result },
    );
}
