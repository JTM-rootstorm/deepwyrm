extern crate std;

use super::*;

use deepwyrm_abi::{
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_WAIT, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_SIGNAL_WRITABLE,
};

use crate::handle::{AcceptedObjectTypes, HandleTable};
use crate::task::CooperativeScheduler;
use std::vec::Vec;

const BYTES: usize = DW_CHANNEL_MAX_PAYLOAD as usize;
type Channels = ChannelAuthority<1, 2>;
type Registry = ObjectRegistry<8>;

const CHANNEL_TRACE_STEPS: usize = 160;
const CHANNEL_TRACE_SEEDS: [u64; 4] = [
    0xf110_0000_0000_0001,
    0xf110_5eed_cafe_babe,
    0x4348_414e_4e45_4c01,
    0x5258_5f52_4553_4552,
];

fn next_channel_trace_random(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn trace_payload(state: &mut u64, step: usize) -> Vec<u8> {
    let random = next_channel_trace_random(state);
    let len = 1 + (random as usize % 3);
    (0..len)
        .map(|offset| random.wrapping_add(step as u64).wrapping_add(offset as u64) as u8)
        .collect()
}

fn pair() -> (
    Registry,
    Channels,
    WaitRegistry<4>,
    [ChannelEndpointKey; 2],
    [HandleRef; 2],
) {
    let mut registry = Registry::new();
    let channels = Channels::new();
    let waits = WaitRegistry::new();
    let (keys, handles) = channels.create_pair(&mut registry).unwrap();
    (registry, channels, waits, keys, handles)
}

fn complete_no_transfer_finalization<
    const OBJECTS: usize,
    const DEPTH: usize,
    const WAITERS: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: ChannelFinalization<DEPTH, WAITERS>,
) -> WakeBatch<WAITERS> {
    let completion = complete_channel_finalization(registry, finalization);
    let (wakes, releases) = completion.into_parts();
    assert!(releases.into_iter().flatten().next().is_none());
    wakes
}

fn finalize(
    registry: &mut Registry,
    channels: &Channels,
    waits: &WaitRegistry<4>,
    handle: HandleRef,
) -> WakeBatch<4> {
    let release = registry.release_handle(handle).unwrap().unwrap();
    let finalization = channels.take_finalization(release, waits).unwrap();
    complete_no_transfer_finalization(registry, finalization)
}

fn make_thread_key(registry: &mut Registry) -> ThreadKey {
    let creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD)
        .unwrap();
    let key = ThreadKey::from_object_id(creation.id());
    registry.cancel_creation(creation).unwrap();
    key
}

fn block_thread(
    registry: &mut Registry,
    scheduler: &CooperativeScheduler<2>,
) -> (ThreadKey, BlockWakeKey) {
    let thread = make_thread_key(registry);
    let reservation = scheduler.reserve(thread).unwrap();
    scheduler.commit(reservation).unwrap();
    scheduler.schedule_next().unwrap();
    let (token, _) = scheduler.block_current(thread).unwrap();
    (thread, token.into_wake_key())
}

fn consume_wakes(
    registry: &mut Registry,
    scheduler: &CooperativeScheduler<2>,
    batch: WakeBatch<4>,
) -> [Option<crate::wait::WakeIntent>; 4] {
    let (wakes, pins) = batch.into_parts();
    for wake in wakes.iter().flatten() {
        scheduler.wake(wake.wake_key()).unwrap();
    }
    for pin in pins.into_iter().flatten() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    wakes
}

#[test]
fn ordered_zero_and_nonzero_datagrams_round_trip() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    assert_eq!(
        channels.current_signals(keys[0]).unwrap(),
        DW_SIGNAL_WRITABLE
    );
    assert_eq!(
        channels.current_signals(keys[1]).unwrap(),
        DW_SIGNAL_WRITABLE
    );
    assert_eq!(channels.send(keys[0], &[], &waits).unwrap().len(), 0);
    assert_eq!(channels.send(keys[0], b"wyrm", &waits).unwrap().len(), 0);
    assert_eq!(
        channels.current_signals(keys[1]).unwrap().0,
        DW_SIGNAL_READABLE.0 | DW_SIGNAL_WRITABLE.0
    );
    let mut output = [0_u8; 8];
    let (first, _) = channels.receive_into(keys[1], &mut output, &waits).unwrap();
    assert_eq!(first, 0);
    let (second, _) = channels.receive_into(keys[1], &mut output, &waits).unwrap();
    assert_eq!(second, 4);
    assert_eq!(&output[..4], b"wyrm");
    let _ = finalize(&mut registry, &channels, &waits, handle0);
    let _ = finalize(&mut registry, &channels, &waits, handle1);
}

#[test]
fn descriptor_backpressure_drives_writable_level() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    assert_eq!(channels.send(keys[0], &[], &waits).unwrap().len(), 0);
    assert_eq!(channels.send(keys[0], &[], &waits).unwrap().len(), 0);
    assert_eq!(
        channels.current_signals(keys[0]).unwrap().0 & DW_SIGNAL_WRITABLE.0,
        0
    );
    assert_eq!(
        channels.send(keys[0], &[], &waits).unwrap_err(),
        ChannelError::WouldBlock
    );
    let mut empty = [];
    let (_, wakes) = channels.receive_into(keys[1], &mut empty, &waits).unwrap();
    assert_eq!(wakes.len(), 0);
    assert_ne!(
        channels.current_signals(keys[0]).unwrap().0 & DW_SIGNAL_WRITABLE.0,
        0
    );
    let _ = finalize(&mut registry, &channels, &waits, handle0);
    let _ = finalize(&mut registry, &channels, &waits, handle1);
}

#[test]
fn buffer_too_small_does_not_consume_head() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    assert_eq!(channels.send(keys[0], b"abcdef", &waits).unwrap().len(), 0);
    assert_eq!(channels.peek_receive(keys[1]).unwrap().required_bytes, 6);
    let mut tiny = [0_u8; 5];
    assert_eq!(
        channels
            .receive_into(keys[1], &mut tiny, &waits)
            .unwrap_err(),
        ChannelError::BufferTooSmall
    );
    assert_eq!(channels.peek_receive(keys[1]).unwrap().required_bytes, 6);
    let mut exact = [0_u8; 6];
    let (_, wakes) = channels.receive_into(keys[1], &mut exact, &waits).unwrap();
    assert_eq!(wakes.len(), 0);
    assert_eq!(&exact, b"abcdef");
    let _ = finalize(&mut registry, &channels, &waits, handle0);
    let _ = finalize(&mut registry, &channels, &waits, handle1);
}

#[test]
fn peer_close_preserves_committed_inbound_message() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    assert_eq!(
        channels.send(keys[0], b"committed", &waits).unwrap().len(),
        0
    );
    let _ = finalize(&mut registry, &channels, &waits, handle0);
    assert_eq!(
        channels.current_signals(keys[1]).unwrap().0,
        DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0
    );
    assert_eq!(
        channels.send(keys[1], b"no peer", &waits).unwrap_err(),
        ChannelError::PeerClosed
    );
    let mut output = [0_u8; 9];
    let (_, wakes) = channels.receive_into(keys[1], &mut output, &waits).unwrap();
    assert_eq!(wakes.len(), 0);
    assert_eq!(&output, b"committed");
    assert_eq!(
        channels.peek_receive(keys[1]).unwrap_err(),
        ChannelError::PeerClosed
    );
    let _ = finalize(&mut registry, &channels, &waits, handle1);
}

#[test]
fn stale_pair_generation_cannot_alias_reused_slot() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    let old_pair = channels.test_pair_key(keys[0]).unwrap();
    let _ = finalize(&mut registry, &channels, &waits, handle0);
    let _ = finalize(&mut registry, &channels, &waits, handle1);
    assert!(!channels.test_pair_key_is_live(old_pair));
    let (next_keys, next_handles) = channels.create_pair(&mut registry).unwrap();
    let [next_handle0, next_handle1] = next_handles;
    let next_pair = channels.test_pair_key(next_keys[0]).unwrap();
    assert_eq!(old_pair.slot, next_pair.slot);
    assert_ne!(old_pair.generation, next_pair.generation);
    assert!(!channels.test_pair_key_is_live(old_pair));
    let _ = finalize(&mut registry, &channels, &waits, next_handle0);
    let _ = finalize(&mut registry, &channels, &waits, next_handle1);
}

#[test]
fn readiness_waiters_wake_on_send_receive_and_peer_close() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    let mut table = HandleTable::<2>::new();
    let endpoint0 = table
        .install(
            handle0,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_CHANNEL),
        )
        .unwrap();
    let endpoint1 = table
        .install(
            handle1,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_CHANNEL),
        )
        .unwrap();
    let scheduler = CooperativeScheduler::<2>::new();

    let (read_thread, read_wake) = block_thread(&mut registry, &scheduler);
    let read_target = table
        .lookup(
            &mut registry,
            endpoint1,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_CHANNEL),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert!(matches!(
        channels
            .register_wait(
                &waits,
                read_target,
                DW_SIGNAL_READABLE,
                7,
                read_thread,
                read_wake,
            )
            .unwrap(),
        ChannelWaitOutcome::Registered(_)
    ));
    let wakes = consume_wakes(
        &mut registry,
        &scheduler,
        channels.send(keys[0], b"x", &waits).unwrap(),
    );
    let wake = wakes.into_iter().flatten().next().unwrap();
    assert_eq!(wake.item_index(), 7);
    assert_ne!(wake.observed().0 & DW_SIGNAL_READABLE.0, 0);
    assert_ne!(wake.observed().0 & DW_SIGNAL_WRITABLE.0, 0);

    assert_eq!(channels.send(keys[0], &[], &waits).unwrap().len(), 0);
    assert_eq!(
        channels.current_signals(keys[0]).unwrap().0 & DW_SIGNAL_WRITABLE.0,
        0
    );
    scheduler.schedule_next().unwrap();
    let (write_token, _) = scheduler.block_current(read_thread).unwrap();
    let write_target = table
        .lookup(
            &mut registry,
            endpoint0,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_CHANNEL),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert!(matches!(
        channels
            .register_wait(
                &waits,
                write_target,
                DW_SIGNAL_WRITABLE,
                3,
                read_thread,
                write_token.into_wake_key(),
            )
            .unwrap(),
        ChannelWaitOutcome::Registered(_)
    ));
    let mut one = [0_u8; 1];
    let (_, write_wakes) = channels.receive_into(keys[1], &mut one, &waits).unwrap();
    let wakes = consume_wakes(&mut registry, &scheduler, write_wakes);
    let wake = wakes.into_iter().flatten().next().unwrap();
    assert_eq!(wake.item_index(), 3);
    assert_ne!(wake.observed().0 & DW_SIGNAL_WRITABLE.0, 0);

    scheduler.schedule_next().unwrap();
    let (close_token, _) = scheduler.block_current(read_thread).unwrap();
    let close_target = table
        .lookup(
            &mut registry,
            endpoint1,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_CHANNEL),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert!(matches!(
        channels
            .register_wait(
                &waits,
                close_target,
                DW_SIGNAL_PEER_CLOSED,
                5,
                read_thread,
                close_token.into_wake_key(),
            )
            .unwrap(),
        ChannelWaitOutcome::Registered(_)
    ));
    let release0 = table.close(&mut registry, endpoint0).unwrap().unwrap();
    let finalization = channels.take_finalization(release0, &waits).unwrap();
    let close_wakes = complete_no_transfer_finalization(&mut registry, finalization);
    let wakes = consume_wakes(&mut registry, &scheduler, close_wakes);
    let wake = wakes.into_iter().flatten().next().unwrap();
    assert_eq!(wake.item_index(), 5);
    assert_ne!(wake.observed().0 & DW_SIGNAL_PEER_CLOSED.0, 0);

    let release1 = table.close(&mut registry, endpoint1).unwrap().unwrap();
    let finalization = channels.take_finalization(release1, &waits).unwrap();
    assert_eq!(
        complete_no_transfer_finalization(&mut registry, finalization).len(),
        0
    );
}

#[test]
fn oversized_payload_is_rejected_without_queue_mutation() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    let payload = std::vec![0x7b_u8; BYTES + 1];
    assert_eq!(
        channels.send(keys[0], &payload, &waits).unwrap_err(),
        ChannelError::InvalidArgument
    );
    assert_eq!(
        channels.peek_receive(keys[1]).unwrap_err(),
        ChannelError::WouldBlock
    );
    assert_eq!(
        channels.current_signals(keys[0]).unwrap(),
        DW_SIGNAL_WRITABLE
    );
    let _ = finalize(&mut registry, &channels, &waits, handle1);
    let _ = finalize(&mut registry, &channels, &waits, handle0);
}

#[test]
fn receive_reservation_stabilizes_head_and_cancels_without_consumption() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    let _ = channels.send(keys[0], b"first", &waits).unwrap();
    let _ = channels.send(keys[0], b"second", &waits).unwrap();

    let reservation = channels.reserve_receive(keys[1]).unwrap();
    assert_eq!(reservation.info().required_bytes, 5);
    assert_eq!(
        channels.reserve_receive(keys[1]).unwrap_err(),
        ChannelError::WouldBlock
    );
    channels.cancel_receive(reservation).unwrap();

    let retry = channels.reserve_receive(keys[1]).unwrap();
    let mut too_small = [0_u8; 4];
    assert!(matches!(
        channels.receive_reserved(retry, &mut too_small, &waits),
        Err(ChannelError::BufferTooSmall)
    ));
    assert_eq!(channels.peek_receive(keys[1]).unwrap().required_bytes, 5);

    let mut output = [0_u8; 6];
    let (first, _) = channels.receive_into(keys[1], &mut output, &waits).unwrap();
    assert_eq!(&output[..first], b"first");
    let (second, _) = channels.receive_into(keys[1], &mut output, &waits).unwrap();
    assert_eq!(&output[..second], b"second");

    let _ = finalize(&mut registry, &channels, &waits, handle0);
    assert_eq!(
        channels.current_signals(keys[1]).unwrap(),
        DW_SIGNAL_PEER_CLOSED
    );
    let _ = finalize(&mut registry, &channels, &waits, handle1);
}

#[test]
fn endpoint_close_order_is_symmetric_for_empty_queues() {
    for close_first in [0_usize, 1_usize] {
        let (mut registry, channels, waits, keys, handles) = pair();
        let [handle0, handle1] = handles;
        let (first, second, peer_key) = if close_first == 0 {
            (handle0, handle1, keys[1])
        } else {
            (handle1, handle0, keys[0])
        };
        let _ = finalize(&mut registry, &channels, &waits, first);
        assert_eq!(
            channels.current_signals(peer_key).unwrap(),
            DW_SIGNAL_PEER_CLOSED
        );
        assert_eq!(
            channels.peek_receive(peer_key).unwrap_err(),
            ChannelError::PeerClosed
        );
        let _ = finalize(&mut registry, &channels, &waits, second);
    }
}

#[test]
fn maximum_payload_fits_one_empty_queue() {
    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    let payload = std::boxed::Box::new([0x5a_u8; BYTES]);
    assert_eq!(
        channels.send(keys[0], &payload[..], &waits).unwrap().len(),
        0
    );
    assert_eq!(
        channels.peek_receive(keys[1]).unwrap().required_bytes,
        DW_CHANNEL_MAX_PAYLOAD
    );
    let mut output = std::boxed::Box::new([0_u8; BYTES]);
    let (actual, _) = channels
        .receive_into(keys[1], &mut output[..], &waits)
        .unwrap();
    assert_eq!(actual, BYTES);
    assert_eq!(output[0], 0x5a);
    assert_eq!(output[BYTES - 1], 0x5a);
    let _ = finalize(&mut registry, &channels, &waits, handle0);
    let _ = finalize(&mut registry, &channels, &waits, handle1);
}

#[test]
fn deterministic_channel_transaction_traces_match_queue_model() {
    for seed in CHANNEL_TRACE_SEEDS {
        let (mut registry, channels, waits, keys, handles) = pair();
        let [handle0, handle1] = handles;
        let mut source_handle = Some(handle0);
        let mut state = seed;
        let mut model = Vec::<Vec<u8>>::new();
        let mut pending_send = None;
        let mut pending_receive = None;
        let mut peer_closed = false;
        let mut saw_send_reservation = false;
        let mut saw_send_cancel = false;
        let mut saw_send_commit = false;
        let mut saw_receive_reservation = false;
        let mut saw_receive_cancel = false;
        let mut saw_backpressure = false;
        let mut saw_peer_close = false;

        for step in 0..CHANNEL_TRACE_STEPS {
            let operation = match step {
                // This deterministic prefix reaches every transaction state once;
                // the fixed-seed suffix then varies the interleavings and payloads.
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 5,
                4 => 6,
                5 => 4,
                6..=8 => 0,
                9 => 4,
                10 => 1,
                11 => 3,
                close_step if close_step == CHANNEL_TRACE_STEPS / 2 => 7,
                _ => next_channel_trace_random(&mut state) % 7,
            };

            match operation {
                // Direct send.
                0 => {
                    let payload = trace_payload(&mut state, step);
                    let actual = channels.send(keys[0], &payload, &waits);
                    if peer_closed {
                        assert!(
                            matches!(actual, Err(ChannelError::InvalidEndpoint)),
                            "Channel trace seed=0x{seed:016x} step={step}: closed source accepted send"
                        );
                    } else if model.len() + usize::from(pending_send.is_some()) >= 2 {
                        assert!(
                            matches!(actual, Err(ChannelError::WouldBlock)),
                            "Channel trace seed=0x{seed:016x} step={step}: full queue admitted send"
                        );
                        saw_backpressure = true;
                    } else {
                        assert!(
                            actual.is_ok(),
                            "Channel trace seed=0x{seed:016x} step={step}: writable queue rejected send: {actual:?}"
                        );
                        model.push(payload);
                    }
                }
                // Send reservation.
                1 => {
                    if pending_send.is_none() {
                        let payload = trace_payload(&mut state, step);
                        let actual = channels.reserve_send(keys[0], &payload);
                        if peer_closed {
                            assert!(
                                matches!(actual, Err(ChannelError::InvalidEndpoint)),
                                "Channel trace seed=0x{seed:016x} step={step}: closed source reserved send"
                            );
                        } else if model.len() >= 2 {
                            assert!(
                                matches!(actual, Err(ChannelError::WouldBlock)),
                                "Channel trace seed=0x{seed:016x} step={step}: full queue reserved send"
                            );
                            saw_backpressure = true;
                        } else {
                            let reservation = actual.unwrap_or_else(|error| {
                                panic!(
                                    "Channel trace seed=0x{seed:016x} step={step}: writable queue rejected reservation: {error:?}"
                                )
                            });
                            pending_send = Some((reservation, payload));
                            saw_send_reservation = true;
                        }
                    }
                }
                // Send cancellation.
                2 => {
                    if let Some((reservation, _)) = pending_send.take() {
                        assert_eq!(
                            channels.cancel_send(reservation),
                            Ok(()),
                            "Channel trace seed=0x{seed:016x} step={step}: fresh send reservation would not cancel"
                        );
                        saw_send_cancel = true;
                    }
                }
                // Send commit.
                3 => {
                    if let Some((reservation, payload)) = pending_send.take() {
                        let actual = channels.commit_send(
                            reservation,
                            crate::handle::HandleTransferBatch::empty(),
                            &waits,
                        );
                        match actual {
                            Ok(_) => {}
                            Err((error, _)) => panic!(
                                "Channel trace seed=0x{seed:016x} step={step}: fresh send reservation would not commit: {error:?}"
                            ),
                        }
                        model.push(payload);
                        saw_send_commit = true;
                    }
                }
                // Direct receive, including intentionally short output buffers.
                4 => {
                    if pending_receive.is_none() {
                        let expected = model.first().cloned();
                        let too_small = expected
                            .as_ref()
                            .is_some_and(|_| next_channel_trace_random(&mut state) & 1 == 0);
                        let output_len = expected.as_ref().map_or(0, |payload| {
                            if too_small {
                                payload.len() - 1
                            } else {
                                payload.len()
                            }
                        });
                        let mut output = [0_u8; 3];
                        let actual =
                            channels.receive_into(keys[1], &mut output[..output_len], &waits);
                        match expected {
                            Some(_payload) if too_small => assert!(
                                matches!(actual, Err(ChannelError::BufferTooSmall)),
                                "Channel trace seed=0x{seed:016x} step={step}: short receive consumed or succeeded"
                            ),
                            Some(payload) => {
                                let (actual_len, wakes) = actual.unwrap_or_else(|error| {
                                    panic!(
                                        "Channel trace seed=0x{seed:016x} step={step}: queued receive failed: {error:?}"
                                    )
                                });
                                assert_eq!(wakes.len(), 0);
                                assert_eq!(actual_len, payload.len());
                                assert_eq!(
                                    &output[..actual_len],
                                    payload.as_slice(),
                                    "Channel trace seed=0x{seed:016x} step={step}: FIFO payload diverged"
                                );
                                model.remove(0);
                            }
                            None if peer_closed => assert!(
                                matches!(actual, Err(ChannelError::PeerClosed)),
                                "Channel trace seed=0x{seed:016x} step={step}: empty peer-closed receive did not fail closed"
                            ),
                            None => assert!(
                                matches!(actual, Err(ChannelError::WouldBlock)),
                                "Channel trace seed=0x{seed:016x} step={step}: empty open receive did not block"
                            ),
                        }
                    }
                }
                // Receive reservation.
                5 => {
                    if pending_receive.is_none() {
                        let actual = channels.reserve_receive(keys[1]);
                        match model.first().cloned() {
                            Some(payload) => {
                                let reservation = actual.unwrap_or_else(|error| {
                                    panic!(
                                        "Channel trace seed=0x{seed:016x} step={step}: queued receive would not reserve: {error:?}"
                                    )
                                });
                                assert_eq!(
                                    reservation.info().required_bytes as usize,
                                    payload.len(),
                                    "Channel trace seed=0x{seed:016x} step={step}: reservation head length diverged"
                                );
                                assert_eq!(reservation.info().required_handles, 0);
                                pending_receive = Some((reservation, payload));
                                saw_receive_reservation = true;
                            }
                            None if peer_closed => assert!(
                                matches!(actual, Err(ChannelError::PeerClosed)),
                                "Channel trace seed=0x{seed:016x} step={step}: peer-closed receive reserved"
                            ),
                            None => assert!(
                                matches!(actual, Err(ChannelError::WouldBlock)),
                                "Channel trace seed=0x{seed:016x} step={step}: empty receive reserved"
                            ),
                        }
                    }
                }
                // Receive cancellation or completion.
                6 => {
                    if let Some((reservation, payload)) = pending_receive.take() {
                        let action = if step == 4 {
                            0
                        } else {
                            next_channel_trace_random(&mut state) % 3
                        };
                        if action == 0 {
                            assert_eq!(
                                channels.cancel_receive(reservation),
                                Ok(()),
                                "Channel trace seed=0x{seed:016x} step={step}: fresh receive reservation would not cancel"
                            );
                            saw_receive_cancel = true;
                        } else {
                            let output_len = if action == 1 {
                                payload.len() - 1
                            } else {
                                payload.len()
                            };
                            let mut output = [0_u8; 3];
                            let actual = channels.receive_reserved(
                                reservation,
                                &mut output[..output_len],
                                &waits,
                            );
                            if action == 1 {
                                assert!(
                                    matches!(actual, Err(ChannelError::BufferTooSmall)),
                                    "Channel trace seed=0x{seed:016x} step={step}: short reserved receive consumed or succeeded"
                                );
                                saw_receive_cancel = true;
                            } else {
                                let received = actual.unwrap_or_else(|error| {
                                    panic!(
                                        "Channel trace seed=0x{seed:016x} step={step}: reserved receive failed: {error:?}"
                                    )
                                });
                                let (actual_len, transfers, wakes) = received.into_parts();
                                assert!(transfers.is_empty());
                                assert_eq!(wakes.len(), 0);
                                assert_eq!(actual_len, payload.len());
                                assert_eq!(&output[..actual_len], payload.as_slice());
                                model.remove(0);
                            }
                        }
                    }
                }
                // Peer-close transition. It is forced once per trace after the
                // reservation/backpressure prefix so queued messages can drain.
                7 => {
                    if !peer_closed {
                        if let Some((reservation, _)) = pending_send.take() {
                            channels.cancel_send(reservation).unwrap();
                        }
                        if let Some((reservation, _)) = pending_receive.take() {
                            channels.cancel_receive(reservation).unwrap();
                        }
                        let _ = finalize(
                            &mut registry,
                            &channels,
                            &waits,
                            source_handle
                                .take()
                                .expect("Channel trace source closes once"),
                        );
                        peer_closed = true;
                        saw_peer_close = true;
                        assert_ne!(
                            channels.current_signals(keys[1]).unwrap().0 & DW_SIGNAL_PEER_CLOSED.0,
                            0,
                            "Channel trace seed=0x{seed:016x} step={step}: peer close signal missing"
                        );
                        assert!(
                            matches!(
                                channels.send(keys[1], b"closed", &waits),
                                Err(ChannelError::PeerClosed)
                            ),
                            "Channel trace seed=0x{seed:016x} step={step}: peer-closed endpoint admitted send"
                        );
                    }
                }
                _ => unreachable!("trace operation is reduced modulo seven"),
            }

            assert!(
                model.len() <= 2,
                "Channel trace seed=0x{seed:016x} step={step}: model exceeded descriptor depth"
            );
            if !peer_closed {
                let writable = model.len() + usize::from(pending_send.is_some()) < 2;
                let signals = channels.current_signals(keys[0]).unwrap();
                assert_eq!(
                    signals.0 & DW_SIGNAL_WRITABLE.0 != 0,
                    writable,
                    "Channel trace seed=0x{seed:016x} step={step}: writable signal diverged"
                );
            }
        }

        if let Some((reservation, _)) = pending_send.take() {
            channels.cancel_send(reservation).unwrap();
        }
        if let Some((reservation, _)) = pending_receive.take() {
            channels.cancel_receive(reservation).unwrap();
        }
        if let Some(handle0) = source_handle.take() {
            let _ = finalize(&mut registry, &channels, &waits, handle0);
        }
        while let Some(payload) = model.first().cloned() {
            let mut output = [0_u8; 3];
            let (actual_len, wakes) = channels
                .receive_into(keys[1], &mut output[..payload.len()], &waits)
                .unwrap();
            assert_eq!(wakes.len(), 0);
            assert_eq!(actual_len, payload.len());
            assert_eq!(&output[..actual_len], payload.as_slice());
            model.remove(0);
        }
        assert_eq!(
            channels.peek_receive(keys[1]),
            Err(ChannelError::PeerClosed)
        );
        let _ = finalize(&mut registry, &channels, &waits, handle1);

        assert!(
            saw_send_reservation,
            "Channel trace seed=0x{seed:016x}: no send reservation"
        );
        assert!(
            saw_send_cancel,
            "Channel trace seed=0x{seed:016x}: no send cancellation"
        );
        assert!(
            saw_send_commit,
            "Channel trace seed=0x{seed:016x}: no send commit"
        );
        assert!(
            saw_receive_reservation,
            "Channel trace seed=0x{seed:016x}: no receive reservation"
        );
        assert!(
            saw_receive_cancel,
            "Channel trace seed=0x{seed:016x}: no receive cancellation"
        );
        assert!(
            saw_backpressure,
            "Channel trace seed=0x{seed:016x}: no backpressure"
        );
        assert!(
            saw_peer_close,
            "Channel trace seed=0x{seed:016x}: no peer close"
        );
    }
}

#[test]
fn concurrent_send_receive_close_trace_preserves_fifo_and_committed_messages() {
    use std::sync::atomic::{AtomicUsize, Ordering as StdOrdering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let mut registry = ObjectRegistry::<8>::new();
    let channels = Arc::new(ChannelAuthority::<1, 4>::new());
    let waits = Arc::new(WaitRegistry::<8>::new());
    let (keys, handles) = channels.create_pair(&mut registry).unwrap();
    let [handle0, handle1] = handles;
    let registry = Arc::new(Mutex::new(registry));
    let sent = Arc::new(Mutex::new(std::vec::Vec::<u8>::new()));
    let received = Arc::new(Mutex::new(std::vec::Vec::<u8>::new()));
    let successful = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(Barrier::new(4));

    let sender = {
        let channels = Arc::clone(&channels);
        let waits = Arc::clone(&waits);
        let sent = Arc::clone(&sent);
        let successful = Arc::clone(&successful);
        let start = Arc::clone(&start);
        thread::spawn(move || {
            start.wait();
            for value in 0_u8..64 {
                loop {
                    match channels.send(keys[0], &[value], &waits) {
                        Ok(wakes) => {
                            assert_eq!(wakes.len(), 0);
                            sent.lock().unwrap().push(value);
                            successful.fetch_add(1, StdOrdering::Release);
                            break;
                        }
                        Err(ChannelError::WouldBlock) => thread::yield_now(),
                        Err(ChannelError::PeerClosed | ChannelError::InvalidEndpoint) => return,
                        Err(error) => panic!("unexpected concurrent Channel send error: {error:?}"),
                    }
                }
            }
        })
    };

    let receiver = {
        let channels = Arc::clone(&channels);
        let waits = Arc::clone(&waits);
        let received = Arc::clone(&received);
        let start = Arc::clone(&start);
        thread::spawn(move || {
            start.wait();
            loop {
                let mut byte = [0_u8; 1];
                match channels.receive_into(keys[1], &mut byte, &waits) {
                    Ok((1, wakes)) => {
                        assert_eq!(wakes.len(), 0);
                        received.lock().unwrap().push(byte[0]);
                    }
                    Ok((other, _)) => panic!("unexpected concurrent receive size {other}"),
                    Err(ChannelError::WouldBlock) => thread::yield_now(),
                    Err(ChannelError::PeerClosed) => break,
                    Err(error) => panic!("unexpected concurrent Channel receive error: {error:?}"),
                }
            }
        })
    };

    let closer = {
        let channels = Arc::clone(&channels);
        let waits = Arc::clone(&waits);
        let registry = Arc::clone(&registry);
        let successful = Arc::clone(&successful);
        let start = Arc::clone(&start);
        thread::spawn(move || {
            start.wait();
            while successful.load(StdOrdering::Acquire) < 16 {
                thread::yield_now();
            }
            let release = registry
                .lock()
                .unwrap()
                .release_handle(handle0)
                .unwrap()
                .unwrap();
            let finalization = channels.take_finalization(release, &waits).unwrap();
            let wakes = {
                let mut registry = registry.lock().unwrap();
                complete_no_transfer_finalization(&mut registry, finalization)
            };
            assert_eq!(wakes.len(), 0);
        })
    };

    start.wait();
    sender.join().unwrap();
    closer.join().unwrap();
    receiver.join().unwrap();

    let sent = sent.lock().unwrap().clone();
    let received = received.lock().unwrap().clone();
    assert!(sent.len() >= 16);
    assert_eq!(
        received, sent,
        "committed Channel datagrams must remain FIFO across peer close"
    );

    let release = registry
        .lock()
        .unwrap()
        .release_handle(handle1)
        .unwrap()
        .unwrap();
    let finalization = channels.take_finalization(release, &waits).unwrap();
    let wakes = {
        let mut registry = registry.lock().unwrap();
        complete_no_transfer_finalization(&mut registry, finalization)
    };
    assert_eq!(wakes.len(), 0);
}

#[test]
fn peer_close_after_transfer_extraction_rolls_back_source_handle_exactly() {
    use crate::handle::HandleMoveRequest;
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_READ,
        DW_RIGHT_TRANSFER,
    };

    let (mut registry, channels, waits, keys, handles) = pair();
    let [handle0, handle1] = handles;
    let mut table = HandleTable::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let reference = registry.creation_into_handle(creation).unwrap();
    let held = deepwyrm_abi::DwRights(
        DW_RIGHT_READ.0 | DW_RIGHT_MAP.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0,
    );
    let source = table.install(reference, held).unwrap();
    let prepared = table
        .prepare_move_batch(&[HandleMoveRequest {
            handle: source,
            requested_rights: deepwyrm_abi::DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0),
        }])
        .unwrap();
    let send = channels.reserve_send(keys[0], b"race").unwrap();
    let (rollback, transfers) = prepared.extract();
    let peer_release = registry.release_handle(handle1).unwrap().unwrap();
    let peer_finalization = channels.take_finalization(peer_release, &waits).unwrap();
    let completion = complete_channel_finalization(&mut registry, peer_finalization);
    let (wakes, releases) = completion.into_parts();
    assert_eq!(wakes.len(), 0);
    assert!(releases.into_iter().flatten().next().is_none());

    let (error, transfers) = channels.commit_send(send, transfers, &waits).unwrap_err();
    assert_eq!(error, ChannelError::PeerClosed);
    rollback.rollback(transfers);
    assert_eq!(table.inspect_basic(source).unwrap().rights, held);

    let source_final = table.close(&mut registry, source).unwrap().unwrap();
    registry.complete_finalization(source_final).unwrap();
    let endpoint_release = registry.release_handle(handle0).unwrap().unwrap();
    let endpoint_finalization = channels
        .take_finalization(endpoint_release, &waits)
        .unwrap();
    let completion = complete_channel_finalization(&mut registry, endpoint_finalization);
    let (wakes, releases) = completion.into_parts();
    assert_eq!(wakes.len(), 0);
    assert!(releases.into_iter().flatten().next().is_none());
}

#[test]
fn reciprocal_transfer_reservations_are_serialized_at_commit() {
    use crate::handle::HandleMoveRequest;
    use deepwyrm_abi::{
        DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DwRights,
    };

    let mut registry = ObjectRegistry::<8>::new();
    let channels = ChannelAuthority::<2, 2>::new();
    let waits = WaitRegistry::<4>::new();
    let (a_keys, a_refs) = channels.create_pair(&mut registry).unwrap();
    let (b_keys, b_refs) = channels.create_pair(&mut registry).unwrap();
    let mut table = HandleTable::<4>::new();
    let held =
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    let [a0, a1] = a_refs.map(|reference| table.install(reference, held).unwrap());
    let [b0, b1] = b_refs.map(|reference| table.install(reference, held).unwrap());

    let prepared_b0 = table
        .prepare_move_batch(&[HandleMoveRequest {
            handle: b0,
            requested_rights: DW_RIGHT_READ,
        }])
        .unwrap();
    let a_to_b = channels.reserve_send(a_keys[1], &[]).unwrap();
    let (b0_rollback, b0_transfer) = prepared_b0.extract();
    let first_wakes = match channels.commit_send(a_to_b, b0_transfer, &waits) {
        Ok(wakes) => wakes,
        Err((error, _)) => panic!("first acyclic transfer was rejected: {error:?}"),
    };
    assert_eq!(first_wakes.len(), 0);
    b0_rollback.finish();

    let prepared_a0 = table
        .prepare_move_batch(&[HandleMoveRequest {
            handle: a0,
            requested_rights: DW_RIGHT_READ,
        }])
        .unwrap();
    let b_to_a = channels.reserve_send(b_keys[1], &[]).unwrap();
    let (a0_rollback, a0_transfer) = prepared_a0.extract();
    let (error, a0_transfer) = channels
        .commit_send(b_to_a, a0_transfer, &waits)
        .unwrap_err();
    assert_eq!(error, ChannelError::InvalidArgument);
    a0_rollback.rollback(a0_transfer);
    assert_eq!(table.inspect_basic(a0).unwrap().rights, held);

    let receive = channels.reserve_receive(a_keys[0]).unwrap();
    let destinations = table.reserve_transfer_batch(1).unwrap();
    let received = channels.receive_reserved(receive, &mut [], &waits).unwrap();
    let (_, transfers, wakes) = received.into_parts();
    assert_eq!(wakes.len(), 0);
    let published = destinations.publish(transfers);
    let received_b0 = published[0].unwrap().handle;

    for handle in [a0, a1, b1, received_b0] {
        let release = table.close(&mut registry, handle).unwrap().unwrap();
        let finalization = channels.take_finalization(release, &waits).unwrap();
        let completion = complete_channel_finalization(&mut registry, finalization);
        let (wakes, releases) = completion.into_parts();
        assert_eq!(wakes.len(), 0);
        assert!(releases.into_iter().flatten().next().is_none());
    }
}

#[test]
fn exhausted_vacant_pair_slot_does_not_mask_later_slots() {
    let mut registry = ObjectRegistry::<4>::new();
    let channels = ChannelAuthority::<2, 1>::new();
    let waits = WaitRegistry::<1>::new();
    channels.test_set_pair_generation(0, u32::MAX);
    let (keys, handles) = channels.create_pair(&mut registry).unwrap();
    assert_eq!(channels.test_pair_key(keys[0]).unwrap().slot, 1);
    for handle in handles {
        let release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = channels.take_finalization(release, &waits).unwrap();
        let completion = complete_channel_finalization(&mut registry, finalization);
        let (wakes, releases) = completion.into_parts();
        assert_eq!(wakes.len(), 0);
        assert!(releases.into_iter().flatten().next().is_none());
    }
}

/// The two "try again" refusals must stay distinguishable inside the kernel.
///
/// Card R1 spent three VM runs unable to say which resource refused a report
/// send, because a full peer queue and an exhausted payload pool both arrived as
/// `WouldBlock`. They clear on different events -- a full peer queue when that
/// peer receives, an exhausted pool when *any* channel releases a slot -- so they
/// are different answers to "when should I retry".
///
/// The exhaustion path itself is deliberately not exercised here. `PayloadPool`
/// is `PAYLOAD_POOL_SLOTS` entries of `DW_CHANNEL_MAX_PAYLOAD` bytes, so a local
/// instance is a megabyte and overflows the test thread's stack, while the real
/// pool is a `static` shared by every test in this binary -- draining it would
/// make unrelated IPC tests fail by resource starvation rather than by defect.
/// Covering it needs the pool to become an owned instance with a caller-chosen
/// capacity, which is a refactor and not a test.
#[test]
fn queue_full_and_payload_exhaustion_are_distinct_within_the_kernel() {
    assert_ne!(ChannelError::WouldBlock, ChannelError::PayloadExhausted);
    // An empty payload takes no slot at all, which is why folding pool
    // availability into DW_SIGNAL_WRITABLE would be wrong as a blanket rule: it
    // would deny a zero-length send that can in fact always proceed.
    assert_eq!(PAYLOAD_POOL.allocate(&[]), Ok(None));
}

/// The small class exists so the pool stops deciding how many datagrams may be
/// in flight. Every non-empty send used to take one of sixteen 64 KiB slots, so
/// a 64-byte record reserved 64 KiB and one busy channel could deny an unrelated
/// one -- card R1's probe was refused at its report-send site while the pool held
/// a megabyte for sixteen tiny records.
#[test]
fn small_payloads_do_not_consume_the_large_class() {
    // More small sends than the large class has slots, all admitted.
    let mut tokens = std::vec::Vec::new();
    for _ in 0..(PAYLOAD_POOL_SLOTS * 4) {
        let token = PAYLOAD_POOL
            .allocate(&[0xab; 64])
            .expect("a small payload is admitted")
            .expect("a non-empty payload takes a slot");
        tokens.push(token);
    }
    // The large class is untouched, so a maximum-size send still fits.
    let large = PAYLOAD_POOL
        .allocate(&[0xcd; PAYLOAD_BYTES])
        .expect("the large class is still free")
        .expect("a non-empty payload takes a slot");
    PAYLOAD_POOL.release(large);
    for token in tokens {
        PAYLOAD_POOL.release(token);
    }
}

/// Round-tripping must read back what was written, for both classes, and a
/// released slot must be reusable.
#[test]
fn both_classes_round_trip_their_bytes() {
    for len in [1_usize, 64, SMALL_PAYLOAD_BYTES, SMALL_PAYLOAD_BYTES + 1] {
        let mut payload = std::vec::Vec::new();
        for index in 0..len {
            payload.push((index % 251) as u8);
        }
        let token = PAYLOAD_POOL
            .allocate(&payload)
            .expect("payload is admitted")
            .expect("a non-empty payload takes a slot");
        let mut output = std::vec![0_u8; len];
        PAYLOAD_POOL.copy_and_release(token, len, &mut output);
        assert_eq!(output, payload, "payload of {len} bytes round-tripped");
    }
}

/// A send just over the small bound belongs to the large class, and one at the
/// bound does not. The boundary is the whole reason the class is safe to add.
#[test]
fn the_small_bound_is_exact() {
    let at_bound = PAYLOAD_POOL
        .allocate(&[0_u8; SMALL_PAYLOAD_BYTES])
        .unwrap()
        .unwrap();
    assert_eq!(at_bound.class, PayloadClass::Small);
    PAYLOAD_POOL.release(at_bound);

    let over_bound = PAYLOAD_POOL
        .allocate(&[0_u8; SMALL_PAYLOAD_BYTES + 1])
        .unwrap()
        .unwrap();
    assert_eq!(over_bound.class, PayloadClass::Large);
    PAYLOAD_POOL.release(over_bound);
}

/// The two refusals share one ABI status on purpose -- a caller must wait and
/// retry for both, so branching on the difference would be a mistake to invite --
/// but whoever is diagnosing a run that waited and never got room is not the
/// caller. The counters are how that reader tells them apart without widening
/// the ABI; card R1's run 13 exited on `WOULD_BLOCK` at the probe's report-send
/// site and could not say which resource had refused.
///
/// This reads the source rather than exercising the counters, because the
/// counters are process-global and the pool is a shared `static`: a test that
/// exhausted either to observe a count would race every other test in this
/// module, which is exactly what the first version of it did. The counting
/// logic itself is covered in `debug::liveness`, against a local snapshot.
#[test]
fn both_refusal_sites_name_their_own_resource() {
    const SOURCE: &str = include_str!("mod.rs");

    let allocate = crate::source_text::fn_body(SOURCE, "fn allocate(&self, payload: &[u8])");
    assert!(
        allocate.contains("ChannelRefusal::PayloadExhausted"),
        "an exhausted payload pool is no longer counted, so a run that waited \
         and never got room cannot say which resource refused"
    );
    assert!(
        !allocate.contains("ChannelRefusal::QueueFull"),
        "the allocator counts a payload refusal as a full queue"
    );

    let reserve = crate::source_text::fn_body(SOURCE, "fn reserve_send(&mut self)");
    assert_eq!(
        reserve.matches("ChannelRefusal::QueueFull").count(),
        reserve.matches("ChannelError::WouldBlock").count(),
        "every WouldBlock in reserve_send must be counted, and counted as a \
         full queue"
    );
    assert!(
        !reserve.contains("ChannelRefusal::PayloadExhausted"),
        "reserve_send counts a queue refusal as an exhausted pool"
    );
}
