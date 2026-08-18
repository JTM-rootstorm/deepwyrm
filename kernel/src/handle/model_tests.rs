extern crate std;

use deepwyrm_abi::{
    DW_HANDLE_INVALID, DW_OBJECT_TYPE_EVENT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DwHandle, DwRights, dw_rights_are_compatible,
    dw_rights_are_known,
};
use std::{format, vec::Vec};

use crate::object::ObjectRegistry;

use super::{AcceptedObjectTypes, HandleTable, HandleTableError};

const TRACE_CAPACITY: usize = 8;
const TRACE_STEPS: usize = 4096;
const TRACE_SEEDS: [u64; 4] = [
    0xd600_0000_0000_0001,
    0xd600_5eed_cafe_babe,
    0x4f42_4a45_4354_0001,
    0x4841_4e44_4c45_0001,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModelEntry {
    handle: DwHandle,
    rights: DwRights,
}

fn rights(bits: &[DwRights]) -> DwRights {
    DwRights(bits.iter().fold(0_u64, |mask, right| mask | right.0))
}
fn next_random(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn find_model(entries: &[ModelEntry], handle: DwHandle) -> Option<ModelEntry> {
    entries.iter().copied().find(|entry| entry.handle == handle)
}

fn expected_duplicate(
    entries: &[ModelEntry],
    source: DwHandle,
    requested: DwRights,
) -> Result<(), HandleTableError> {
    if requested.0 == 0 || !dw_rights_are_known(requested) {
        return Err(HandleTableError::InvalidRights);
    }
    let source = find_model(entries, source).ok_or(HandleTableError::InvalidHandle)?;
    if !dw_rights_are_compatible(DW_OBJECT_TYPE_EVENT, requested) {
        return Err(HandleTableError::InvalidRights);
    }
    if source.rights.0 & DW_RIGHT_DUPLICATE.0 == 0 {
        return Err(HandleTableError::AccessDenied);
    }
    if requested.0 & !source.rights.0 != 0 {
        return Err(HandleTableError::AccessDenied);
    }
    if entries.len() >= TRACE_CAPACITY {
        return Err(HandleTableError::Capacity);
    }
    Ok(())
}

fn expected_lookup(
    entries: &[ModelEntry],
    handle: DwHandle,
    required: DwRights,
) -> Result<ModelEntry, HandleTableError> {
    if !dw_rights_are_known(required) {
        return Err(HandleTableError::InvalidRights);
    }
    let entry = find_model(entries, handle).ok_or(HandleTableError::InvalidHandle)?;
    if !dw_rights_are_compatible(DW_OBJECT_TYPE_EVENT, required) {
        return Err(HandleTableError::InvalidRights);
    }
    if entry.rights.0 & required.0 != required.0 {
        return Err(HandleTableError::AccessDenied);
    }
    Ok(entry)
}

fn choose_handle(state: &mut u64, live: &[ModelEntry], stale: &[DwHandle]) -> DwHandle {
    let random = next_random(state);
    if !stale.is_empty() && random & 0x7 == 0 {
        stale[(random as usize >> 3) % stale.len()]
    } else {
        live[(random as usize >> 3) % live.len()].handle
    }
}
#[test]
fn deterministic_handle_traces_match_abstract_model() {
    let initial_rights = rights(&[
        DW_RIGHT_WAIT,
        DW_RIGHT_DUPLICATE,
        DW_RIGHT_INSPECT,
        DW_RIGHT_TRANSFER,
    ]);

    for seed in TRACE_SEEDS {
        let mut state = seed;
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
        let reference = registry.creation_into_handle(creation).unwrap();
        let mut table = HandleTable::<TRACE_CAPACITY>::new();
        let initial = table.install(reference, initial_rights).unwrap();
        let lifetime_pin = table
            .lookup(
                &mut registry,
                initial,
                AcceptedObjectTypes::Any,
                DwRights(0),
            )
            .unwrap();
        let mut live = Vec::from([ModelEntry {
            handle: initial,
            rights: initial_rights,
        }]);
        let mut stale = Vec::new();
        let mut failure = None;
        for step in 0..TRACE_STEPS {
            let operation = next_random(&mut state) % 5;
            match operation {
                0 | 1 => {
                    let source = choose_handle(&mut state, &live, &stale);
                    let source_rights =
                        find_model(&live, source).map_or(initial_rights, |entry| entry.rights);
                    let requested = match next_random(&mut state) % 7 {
                        0 => source_rights,
                        1 => DW_RIGHT_WAIT,
                        2 => rights(&[DW_RIGHT_WAIT, DW_RIGHT_INSPECT]),
                        3 => DwRights(0),
                        4 => DwRights(1_u64 << 63),
                        5 => DW_RIGHT_READ,
                        _ => initial_rights,
                    };
                    let expected = expected_duplicate(&live, source, requested);
                    let actual = table.duplicate(&mut registry, source, requested);
                    match (expected, actual) {
                        (Ok(()), Ok(handle)) => live.push(ModelEntry {
                            handle,
                            rights: requested,
                        }),
                        (Err(expected), Err(actual)) if expected == actual => {}
                        (expected, actual) => {
                            failure = Some(format!(
                                "step {step}: duplicate mismatch: expected {expected:?}, got {actual:?}"
                            ));
                            break;
                        }
                    }
                }
                2 => {
                    let target = if live.len() > 1 {
                        choose_handle(&mut state, &live, &stale)
                    } else {
                        stale.last().copied().unwrap_or(DW_HANDLE_INVALID)
                    };
                    let model_index = live.iter().position(|entry| entry.handle == target);
                    let actual = table.close(&mut registry, target);
                    match (model_index, actual) {
                        (Some(index), Ok(None)) => {
                            let closed = live.swap_remove(index);
                            stale.push(closed.handle);
                        }
                        (None, Err(HandleTableError::InvalidHandle)) => {}
                        (expected, actual) => {
                            failure = Some(format!(
                                "step {step}: close mismatch: model index {expected:?}, got {actual:?}"
                            ));
                            break;
                        }
                    }
                }
                3 => {
                    let target = choose_handle(&mut state, &live, &stale);
                    let required = match next_random(&mut state) % 5 {
                        0 => DwRights(0),
                        1 => DW_RIGHT_WAIT,
                        2 => DW_RIGHT_TRANSFER,
                        3 => DW_RIGHT_READ,
                        _ => DwRights(1_u64 << 63),
                    };
                    let expected = expected_lookup(&live, target, required);
                    let actual =
                        table.lookup(&mut registry, target, AcceptedObjectTypes::Any, required);
                    match (expected, actual) {
                        (Ok(expected), Ok(resolved)) => {
                            if resolved.object_type() != DW_OBJECT_TYPE_EVENT
                                || resolved.rights() != expected.rights
                            {
                                failure = Some(format!(
                                    "step {step}: lookup metadata mismatch for {target:?}"
                                ));
                            }
                            let released = registry
                                .release_internal(resolved.into_internal())
                                .expect("trace lookup pin must be releasable");
                            if released.is_some() {
                                failure = Some(format!(
                                    "step {step}: temporary lookup unexpectedly finalized object"
                                ));
                            }
                            if failure.is_some() {
                                break;
                            }
                        }
                        (Err(expected), Err(actual)) if expected == actual => {}
                        (expected, Ok(resolved)) => {
                            let _ = registry.release_internal(resolved.into_internal());
                            failure = Some(format!(
                                "step {step}: lookup mismatch: expected {expected:?}, got success"
                            ));
                            break;
                        }
                        (expected, Err(actual)) => {
                            failure = Some(format!(
                                "step {step}: lookup mismatch: expected {expected:?}, got {actual:?}"
                            ));
                            break;
                        }
                    }
                }
                _ => {
                    let target = choose_handle(&mut state, &live, &stale);
                    let expected = match find_model(&live, target) {
                        None => Err(HandleTableError::InvalidHandle),
                        Some(entry) if entry.rights.0 & DW_RIGHT_INSPECT.0 == 0 => {
                            Err(HandleTableError::AccessDenied)
                        }
                        Some(entry) => Ok(entry),
                    };
                    let actual = table.inspect_basic(target);
                    match (expected, actual) {
                        (Ok(expected), Ok(actual))
                            if actual.object_type == DW_OBJECT_TYPE_EVENT
                                && actual.rights == expected.rights => {}
                        (Err(expected), Err(actual)) if expected == actual => {}
                        (expected, actual) => {
                            failure = Some(format!(
                                "step {step}: inspect mismatch: expected {expected:?}, got {actual:?}"
                            ));
                            break;
                        }
                    }
                }
            }

            if table.len() != live.len() {
                failure = Some(format!(
                    "step {step}: live-count mismatch: model {}, table {}",
                    live.len(),
                    table.len()
                ));
                break;
            }
            let sample = live[(next_random(&mut state) as usize) % live.len()];
            match table.lookup(
                &mut registry,
                sample.handle,
                AcceptedObjectTypes::Any,
                DwRights(0),
            ) {
                Ok(resolved) => {
                    if resolved.rights() != sample.rights {
                        failure = Some(format!(
                            "step {step}: sampled rights diverged from abstract model"
                        ));
                    }
                    let released = registry
                        .release_internal(resolved.into_internal())
                        .expect("sample lookup pin must release");
                    if released.is_some() {
                        failure = Some(format!(
                            "step {step}: sampled lookup unexpectedly finalized object"
                        ));
                    }
                }
                Err(error) => {
                    failure = Some(format!(
                        "step {step}: model-live sampled handle failed lookup: {error:?}"
                    ));
                }
            }
            if failure.is_some() {
                break;
            }
        }
        let drained = table.drain(&mut registry);
        if drained.final_release_count() != 0 && failure.is_none() {
            failure = Some(format!(
                "drain returned {} finalizers while the trace lifetime pin was live",
                drained.final_release_count()
            ));
        }
        for final_release in drained.into_final_releases().into_iter().flatten() {
            let _ = registry.complete_finalization(final_release);
        }

        let final_release = registry
            .release_internal(lifetime_pin.into_internal())
            .expect("trace lifetime pin must release");
        if let Some(final_release) = final_release {
            registry.complete_finalization(final_release).unwrap();
        } else if failure.is_none() {
            failure = Some("trace lifetime pin was not the final object reference".into());
        }

        if let Some(failure) = failure {
            panic!("deterministic handle trace seed=0x{seed:016x}: {failure}");
        }
    }
}

#[test]
fn lookup_close_duplicate_linearization_preserves_exact_authority() {
    let held = rights(&[DW_RIGHT_WAIT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT]);
    let reduced = rights(&[DW_RIGHT_WAIT, DW_RIGHT_INSPECT]);
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
    let reference = registry.creation_into_handle(creation).unwrap();
    let mut table = HandleTable::<2>::new();
    let source = table.install(reference, held).unwrap();

    let lookup = table
        .lookup(
            &mut registry,
            source,
            AcceptedObjectTypes::Any,
            DW_RIGHT_WAIT,
        )
        .unwrap();
    let duplicate = table.duplicate(&mut registry, source, reduced).unwrap();

    assert!(table.close(&mut registry, source).unwrap().is_none());
    assert_eq!(
        table.lookup(&mut registry, source, AcceptedObjectTypes::Any, DwRights(0),),
        Err(HandleTableError::InvalidHandle)
    );
    let duplicate_info = table.inspect_basic(duplicate).unwrap();
    assert_eq!(duplicate_info.object_type, DW_OBJECT_TYPE_EVENT);
    assert_eq!(duplicate_info.rights, reduced);

    assert!(
        registry
            .release_internal(lookup.into_internal())
            .unwrap()
            .is_none(),
        "published duplicate remains a strong owner after the lookup pin releases"
    );
    let final_release = table
        .close(&mut registry, duplicate)
        .unwrap()
        .expect("last published handle becomes final after the lookup pin is gone");
    registry.complete_finalization(final_release).unwrap();
}
