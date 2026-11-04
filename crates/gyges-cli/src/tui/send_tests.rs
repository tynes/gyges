//! Tests of the send modal (`tui::send`): every stage, driven by keys and
//! by the updates the send task would send.

use std::time::Duration;

use crossterm::event::KeyCode;
use gyges_proto::v1::{
    AddressKind, InspectAddressResponse, Pool, Proposal, ProposalStep, ProposedOutput,
    SignatureKind, SignatureRequired, SigningMode,
};
use gyges_qr::Frames;

use super::*;
use crate::tui::app::tests::{info_with, key, press};
use crate::tui::app::{Action, App, Event};
use crate::tui::ui::tests::render;

fn app_with(mode: SigningMode) -> App {
    let mut app = App::new(Duration::from_secs(2));
    let mut k = key("main", true);
    k.signing_mode = mode as i32;
    app.on_event(Event::Info(Box::new(info_with(vec![k]))));
    app
}

fn typed(app: &mut App, s: &str) {
    for c in s.chars() {
        press(app, KeyCode::Char(c));
    }
}

fn proposal() -> Proposal {
    Proposal {
        steps: vec![ProposalStep {
            index: 1,
            outputs: vec![ProposedOutput {
                address: "uregtest1recipient".into(),
                pool: Pool::Ironwood as i32,
                value: 50_000_000,
                ..Default::default()
            }],
            fee: 10_000,
            ..Default::default()
        }],
        total_debit: 50_010_000,
        total_fee: 10_000,
        ..Default::default()
    }
}

fn update(app: &mut App, u: SendUpdate) {
    let id = app.send_id;
    app.on_event(Event::Send { id, update: u });
}

/// Fill the form, review, confirm: the real request is out.
fn to_running(app: &mut App) -> SendSpec {
    press(app, KeyCode::Char('s'));
    typed(app, "uregtest1recipient");
    press(app, KeyCode::Tab);
    typed(app, "0.5");
    press(app, KeyCode::Enter);
    let spec = match app.take_actions().as_slice() {
        [Action::DryRun { spec, .. }] => spec.clone(),
        other => panic!("{other:?}"),
    };
    update(app, SendUpdate::DryRun(Ok(proposal())));
    press(app, KeyCode::Enter);
    assert!(matches!(
        app.take_actions().as_slice(),
        [Action::Execute { .. }]
    ));
    spec
}

#[test]
fn the_form_validates_before_anything_is_asked() {
    let mut f = Form::new(Flow::Send, "main".into());
    assert!(f.validate().unwrap_err().contains("recipient"));
    f.to = "t1abc".into();
    f.amount = "1,5".into();
    assert!(f.validate().unwrap_err().starts_with("amount:"));
    f.amount = "max".into();
    f.memo = "hi".into();
    f.inspect = Some((
        "t1abc".into(),
        Ok(InspectAddressResponse {
            valid: true,
            kind: AddressKind::TransparentP2pkh as i32,
            ..Default::default()
        }),
    ));
    assert!(
        f.validate()
            .unwrap_err()
            .contains("shielded recipients only")
    );
    f.memo.clear();
    f.out_pool = 2;
    f.from = 1;
    let spec = f.validate().unwrap();
    assert_eq!(spec.amount, Some(ParsedAmount::Max));
    let req = spec.send_request(true);
    assert!(req.dry_run);
    let opts = req.options.unwrap();
    assert_eq!(opts.output_pool, Pool::Sapling as i32);
    assert_eq!(opts.from_pools, vec![Pool::Ironwood as i32]);

    let mut s = Form::new(Flow::Shield, "main".into());
    assert_eq!(s.validate().unwrap().threshold, 0);
    s.threshold = "0.5".into();
    assert_eq!(
        s.validate().unwrap().shield_request(false).threshold,
        50_000_000
    );
    s.threshold = "max".into();
    assert!(s.validate().is_err());
}

#[test]
fn the_recipient_is_inspected_once_typing_pauses() {
    let mut app = app_with(SigningMode::LocalSeed);
    press(&mut app, KeyCode::Char('s'));
    typed(&mut app, "uregtest1x");
    let now = app.now;
    app.on_tick(now);
    assert!(app.take_actions().is_empty(), "not yet");
    app.on_tick(now + Duration::from_secs(1));
    assert_eq!(
        app.take_actions(),
        vec![Action::Inspect("uregtest1x".into())]
    );
    app.on_event(Event::Inspected {
        address: "uregtest1x".into(),
        result: Ok(InspectAddressResponse {
            valid: false,
            error: "bad checksum".into(),
            ..Default::default()
        }),
    });
    let s = render(&app, 140, 30);
    assert!(s.contains("invalid: bad checksum"), "{s}");
    press(&mut app, KeyCode::Tab);
    typed(&mut app, "1");
    press(&mut app, KeyCode::Enter);
    assert!(render(&app, 140, 30).contains("the address is not valid"));
    assert!(app.take_actions().is_empty());
}

#[test]
fn a_passphrase_send_from_form_to_txid() {
    let mut app = app_with(SigningMode::LocalSeed);
    let spec = to_running(&mut app);
    assert_eq!(spec.to, "uregtest1recipient");
    assert_eq!(spec.amount, Some(ParsedAmount::Zatoshis(50_000_000)));

    update(
        &mut app,
        SendUpdate::Proving {
            pool: Pool::Orchard,
            done: 0,
            total: 2,
        },
    );
    update(
        &mut app,
        SendUpdate::NeedPassphrase {
            key_id: "main".into(),
        },
    );
    typed(&mut app, "hunter2");
    let s = render(&app, 140, 30);
    assert!(s.contains("passphrase for main: •••••••"), "{s}");
    assert!(!s.contains("hunter2"), "masked: {s}");
    press(&mut app, KeyCode::Enter);
    let acts = app.take_actions();
    assert_eq!(
        acts,
        vec![Action::Reply(SendReply::Passphrase("hunter2".into()))]
    );
    assert!(!format!("{acts:?}").contains("hunter2"), "never printed");

    update(
        &mut app,
        SendUpdate::PassphraseRefused("wrong passphrase (1 of 3)".into()),
    );
    assert!(render(&app, 140, 30).contains("wrong passphrase (1 of 3)"));
    typed(&mut app, "right");
    press(&mut app, KeyCode::Enter);
    app.take_actions();
    update(&mut app, SendUpdate::Signed(1));
    update(
        &mut app,
        SendUpdate::Broadcast {
            step: 1,
            txid: "ab".repeat(32),
        },
    );
    update(&mut app, SendUpdate::Ended(Ok(())));
    assert_eq!(app.take_actions(), vec![Action::Refresh]);
    let s = render(&app, 140, 30);
    assert!(s.contains(&"ab".repeat(32)) && s.contains("Done."), "{s}");
    assert!(
        app.toasts
            .iter()
            .any(|t| t.text.starts_with("Send: broadcast abab"))
    );
    press(&mut app, KeyCode::Enter);
    assert!(app.send.is_none());
}

#[test]
fn the_confirmation_shows_the_proposal_and_esc_goes_back() {
    let mut app = app_with(SigningMode::LocalSeed);
    press(&mut app, KeyCode::Char('s'));
    typed(&mut app, "uregtest1recipient");
    press(&mut app, KeyCode::Tab);
    typed(&mut app, "0.5");
    press(&mut app, KeyCode::Enter);
    app.take_actions();
    update(&mut app, SendUpdate::DryRun(Ok(proposal())));
    let s = render(&app, 140, 30);
    assert!(s.contains("Total debit: 0.50010000 ZEC"), "{s}");
    assert!(s.contains("Send 0.50010000 ZEC in total?"), "{s}");
    press(&mut app, KeyCode::Esc);
    assert!(matches!(app.send, Some(Stage::Form(_))));
    assert!(app.take_actions().is_empty(), "nothing was sent");

    // A refused dry run returns to the form with the reason.
    press(&mut app, KeyCode::Enter);
    app.take_actions();
    update(
        &mut app,
        SendUpdate::DryRun(Err("insufficient funds".into())),
    );
    assert!(render(&app, 140, 30).contains("insufficient funds"));
}

#[test]
fn the_passphrase_field_survives_a_missed_poll_and_takes_a_paste() {
    let mut app = app_with(SigningMode::LocalSeed);
    to_running(&mut app);
    update(
        &mut app,
        SendUpdate::NeedPassphrase {
            key_id: "main".into(),
        },
    );
    typed(&mut app, "ab");
    app.on_event(Event::Down {
        error: "gygesd is not running".into(),
    });
    let s = render(&app, 140, 30);
    assert!(
        s.contains("passphrase for main: ••"),
        "still on screen: {s}"
    );
    app.on_paste("cd-ef\n");
    assert!(render(&app, 140, 30).contains("passphrase for main: •••••••"));
    press(&mut app, KeyCode::Enter);
    let acts = app.take_actions();
    assert_eq!(
        acts,
        vec![Action::Reply(SendReply::Passphrase("abcd-ef".into()))]
    );
    assert!(!format!("{acts:?}").contains("abcd"), "never printed");
}

#[test]
fn cancelling_the_passphrase_tells_the_task() {
    let mut app = app_with(SigningMode::LocalSeed);
    to_running(&mut app);
    update(
        &mut app,
        SendUpdate::NeedPassphrase {
            key_id: "main".into(),
        },
    );
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.take_actions(), vec![Action::Reply(SendReply::Cancel)]);
    update(
        &mut app,
        SendUpdate::Ended(Err("cancelled: nothing was signed".into())),
    );
    assert!(render(&app, 140, 30).contains("cancelled: nothing was signed"));
}

#[test]
fn a_keystone_send_shows_the_request_and_takes_a_pasted_answer() {
    let mut app = app_with(SigningMode::KeystoneQr);
    to_running(&mut app);
    let payload: Vec<u8> = (0..600u32).map(|i| (i * 13) as u8).collect();
    update(
        &mut app,
        SendUpdate::NeedKeystone(Box::new(SignatureRequired {
            key_id: "main".into(),
            kind: SignatureKind::KeystoneBatch as i32,
            session_id: "5e55".into(),
            payload: payload.clone(),
            ..Default::default()
        })),
    );
    let s = render(&app, 160, 70);
    assert!(s.contains('█'), "the request's QR code: {s}");
    assert!(s.contains("Scan this with the Keystone (batch"), "{s}");
    // The animation moves on with the clock.
    let first = render(&app, 160, 70);
    app.on_tick(app.now + Duration::from_secs(1));
    assert_ne!(first, render(&app, 160, 70), "the next fountain frame");

    // Pasting the request back is refused; the answer goes through.
    let request = crate::keystone::frame_lines(
        Frames::new(gyges_qr::ur_types::ZCASH_SIGN_BATCH, &payload, 100).unwrap(),
    )
    .unwrap();
    app.on_paste(&request.join("\n"));
    assert!(render(&app, 160, 70).contains("is it the request?"));
    assert!(app.take_actions().is_empty());
    let answer_cbor = vec![0xa1u8, 0x01, 0x02];
    let answer = crate::keystone::frame_lines(
        Frames::new(
            gyges_qr::ur_types::ZCASH_BATCH_SIG_RESULT,
            &answer_cbor,
            100,
        )
        .unwrap(),
    )
    .unwrap();
    app.on_paste(&answer.join("\n"));
    assert_eq!(
        app.take_actions(),
        vec![
            Action::StopScan,
            Action::Reply(SendReply::Keystone(answer_cbor.clone()))
        ]
    );
    update(
        &mut app,
        SendUpdate::KeystoneRefused("bad signature".into()),
    );
    assert!(render(&app, 160, 70).contains("the daemon refused the answer: bad signature"));
    // Typed frames work too, one Enter each.
    typed(&mut app, &answer[0]);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.take_actions(),
        vec![
            Action::StopScan,
            Action::Reply(SendReply::Keystone(answer_cbor))
        ]
    );
    update(&mut app, SendUpdate::Signed(1));
    update(
        &mut app,
        SendUpdate::Broadcast {
            step: 1,
            txid: "cd".repeat(32),
        },
    );
    update(&mut app, SendUpdate::Ended(Ok(())));
    assert!(render(&app, 160, 70).contains(&"cd".repeat(32)));
}

#[test]
fn the_camera_is_asked_with_f2_and_its_answer_is_sent() {
    let mut app = app_with(SigningMode::KeystoneQr);
    to_running(&mut app);
    update(
        &mut app,
        SendUpdate::NeedKeystone(Box::new(SignatureRequired {
            kind: SignatureKind::KeystoneSinglePczt as i32,
            session_id: "5e55".into(),
            payload: vec![1, 2, 3],
            ..Default::default()
        })),
    );
    press(&mut app, KeyCode::F(2));
    assert_eq!(
        app.take_actions(),
        vec![Action::ScanCamera {
            answer: gyges_qr::ur_types::ZCASH_PCZT,
            request: vec![1, 2, 3]
        }]
    );
    app.on_event(Event::ScanProgress((1, 4)));
    assert!(render(&app, 160, 60).contains("1 of 4 fragments"));
    app.on_event(Event::Scanned(Ok(vec![9])));
    assert_eq!(
        app.take_actions(),
        vec![Action::Reply(SendReply::Keystone(vec![9]))]
    );
    // Leaving keeps the session open (the task says how to finish it).
    let mut app = app_with(SigningMode::KeystoneQr);
    to_running(&mut app);
    update(
        &mut app,
        SendUpdate::NeedKeystone(Box::new(SignatureRequired {
            kind: SignatureKind::KeystoneSinglePczt as i32,
            session_id: "5e55".into(),
            payload: vec![1, 2, 3],
            ..Default::default()
        })),
    );
    app.on_event(Event::Scanned(Err("no camera".into())));
    assert!(render(&app, 160, 60).contains("camera: no camera; paste the frames instead"));
    press(&mut app, KeyCode::Esc);
    assert_eq!(
        app.take_actions(),
        vec![Action::StopScan, Action::Reply(SendReply::Cancel)]
    );
}

#[test]
fn keys_that_cannot_sign_here_do_not_open_the_form() {
    for mode in [SigningMode::WatchOnly, SigningMode::SignerOnly] {
        let mut app = app_with(mode);
        press(&mut app, KeyCode::Char('s'));
        assert!(app.send.is_none());
        assert!(
            app.toasts.last().unwrap().text.contains("main is"),
            "{:?}",
            app.toasts
        );
    }
}

#[test]
fn shield_needs_only_a_threshold_and_stale_answers_are_dropped() {
    let mut app = app_with(SigningMode::LocalSeed);
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Enter);
    let id = match app.take_actions().as_slice() {
        [Action::DryRun { id, spec }] if spec.flow == Flow::Shield => *id,
        other => panic!("{other:?}"),
    };
    // Back out and in again: the first dry run's answer is stale.
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Enter);
    app.take_actions();
    app.on_event(Event::Send {
        id,
        update: SendUpdate::DryRun(Ok(proposal())),
    });
    assert!(
        matches!(app.send, Some(Stage::Proposing(_))),
        "{:?}",
        app.send
    );
    assert_eq!(format!("{:?}", Secret::from("x")), "Secret(…)");
}
