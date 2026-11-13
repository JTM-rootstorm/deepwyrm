use super::*;
use deepwyrm_abi::{
    DW_STATUS_BAD_STATE, DW_STATUS_INVALID_ARGUMENT, DwAddressRegionMapFlags, DwHandle, DwOffset,
    DwSize,
};

const MIB: u64 = 1 << 20;
const STEP: u64 = 16 * MIB;
const REGION: DwHandle = DwHandle(7);
const READ: u32 = 1;
const READ_WRITE: u32 = 3;

type Steps = RegionSteps<u8, 4>;

fn map_request() -> NativeSyscallRequest {
    NativeSyscallRequest::AddressRegionMap {
        address_region: REGION,
        memory_object: DwHandle(9),
        args: DwUserAddress(0x1000),
        args_size: 72,
        out_address: DwUserAddress(0x2000),
    }
}

fn map_args(byte_len: u64, offset: u64, fixed_at: Option<u64>) -> DwAddressRegionMapArgsV1 {
    DwAddressRegionMapArgsV1 {
        memory_object_offset: DwOffset(offset),
        byte_len: DwSize(byte_len),
        requested_address: DwUserAddress(fixed_at.unwrap_or(0)),
        flags: match fixed_at {
            Some(_) => DW_ADDRESS_REGION_MAP_FLAG_FIXED,
            None => DwAddressRegionMapFlags(0),
        },
        ..DwAddressRegionMapArgsV1::default()
    }
}

/// (flags, address, offset, length, room) of a map step.
fn map_step(step: &Step<u8>) -> (u32, u64, u64, u64, u64) {
    let Some(Ok((args, _, room))) = step.map else {
        panic!("not a map step")
    };
    (
        args.flags.0,
        args.requested_address.0,
        args.memory_object_offset.0,
        args.byte_len.0,
        room,
    )
}

/// (address, length, protections) of an unmap (`None`) or protect step.
fn range_step(step: &Step<u8>) -> (u64, u64, Option<u32>) {
    match step.request {
        NativeSyscallRequest::AddressRegionUnmap {
            address_region,
            address,
            byte_len,
        } => {
            assert_eq!(address_region, REGION);
            (address.0, byte_len, None)
        }
        NativeSyscallRequest::AddressRegionProtect {
            address_region,
            address,
            byte_len,
            protections,
        } => {
            assert_eq!(address_region, REGION);
            (address.0, byte_len, Some(protections))
        }
        other => panic!("not a range step: {other:?}"),
    }
}

#[test]
fn a_call_within_one_step_runs_as_it_always_has() {
    let mut steps = Steps::new(map_request(), STEP);
    assert!(steps.needs_map_input());
    steps.set_map_input(Ok((map_args(STEP, 0, None), 0)));
    assert!(!steps.in_steps());
    let step = steps.step();
    assert!(step.last);
    assert_eq!(map_step(&step), (0, 0, 0, STEP, STEP));

    // A refused map is one step carrying its status.
    let mut steps = Steps::new(map_request(), STEP);
    steps.set_map_input(Err(DW_STATUS_INVALID_ARGUMENT));
    let step = steps.step();
    assert!(step.last);
    assert!(matches!(step.map, Some(Err(DW_STATUS_INVALID_ARGUMENT))));

    // A large but misaligned call is one step too, refused as before.
    let unmap = NativeSyscallRequest::AddressRegionUnmap {
        address_region: REGION,
        address: DwUserAddress(0x40_0800),
        byte_len: 3 * STEP,
    };
    assert!(Steps::new(unmap, STEP).step().last);
}

#[test]
fn an_allocator_placed_map_finds_room_for_all_of_it_then_continues_fixed() {
    let mut steps = Steps::new(map_request(), STEP);
    steps.set_map_input(Ok((map_args(40 * MIB, 4 * MIB, None), 0)));
    assert!(steps.in_steps());
    let first = steps.step();
    assert!(!first.last);
    assert_eq!(map_step(&first), (0, 0, 4 * MIB, STEP, 40 * MIB));
    let placed = 0x4000_0000;
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, Some(placed)), None);
    assert_eq!(
        map_step(&steps.step()),
        (1, placed + STEP, 4 * MIB + STEP, STEP, STEP)
    );
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, Some(placed + STEP)), None);
    assert_eq!(
        map_step(&steps.step()),
        (1, placed + 2 * STEP, 4 * MIB + 2 * STEP, 8 * MIB, 8 * MIB)
    );
    assert_eq!(
        steps.advance(DW_STATUS_SUCCESS, Some(placed + 2 * STEP)),
        Some(DW_STATUS_SUCCESS)
    );
    assert_eq!(steps.address(), Some(placed));
}

#[test]
fn a_failed_map_step_unmaps_the_steps_before_it() {
    let base = 0x8000_0000;
    let mut steps = Steps::new(map_request(), STEP);
    steps.set_map_input(Ok((map_args(3 * STEP, 0, Some(base)), 0)));
    assert_eq!(map_step(&steps.step()), (1, base, 0, STEP, STEP));
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, Some(base)), None);
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, Some(base + STEP)), None);
    // The third step fails: the first two are unmapped, a step at a time.
    assert_eq!(steps.advance(DW_STATUS_BAD_STATE, None), None);
    let undo = steps.step();
    assert!(undo.map.is_none() && !undo.last);
    assert_eq!(range_step(&undo), (base, STEP, None));
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, None), None);
    assert_eq!(range_step(&steps.step()), (base + STEP, STEP, None));
    // An undo step's own failure does not change what the call returns.
    assert_eq!(
        steps.advance(DW_STATUS_INVALID_ARGUMENT, None),
        Some(DW_STATUS_BAD_STATE)
    );

    // A first step that fails changed nothing and returns at once.
    let mut steps = Steps::new(map_request(), STEP);
    steps.set_map_input(Ok((map_args(3 * STEP, 0, Some(base)), 0)));
    assert_eq!(
        steps.advance(DW_STATUS_BAD_STATE, None),
        Some(DW_STATUS_BAD_STATE)
    );
}

#[test]
fn a_failed_protect_step_restores_the_old_protections() {
    let base = 0x8000_0000;
    let request = NativeSyscallRequest::AddressRegionProtect {
        address_region: REGION,
        address: DwUserAddress(base),
        byte_len: 3 * STEP,
        protections: READ,
    };
    let mut steps = Steps::new(request, STEP);
    assert_eq!(
        steps.snapshot_range(),
        Some((REGION, base, base + 3 * STEP))
    );
    // Read-write up to 20 MiB in, then read-only; a mapping outside the
    // range is ignored.
    steps.set_snapshot([
        Some((base, 20 * MIB, READ_WRITE)),
        Some((base + 20 * MIB, 3 * STEP - 20 * MIB, READ)),
        Some((base + 3 * STEP, STEP, READ_WRITE)),
        None,
    ]);
    assert_eq!(steps.snapshot_range(), None);
    assert_eq!(range_step(&steps.step()), (base, STEP, Some(READ)));
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, None), None);
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, None), None);
    assert_eq!(steps.advance(DW_STATUS_BAD_STATE, None), None);
    // The two steps made covered 32 MiB: 20 MiB read-write and 12 MiB
    // read-only are restored, the first piece in two steps.
    assert_eq!(range_step(&steps.step()), (base, STEP, Some(READ_WRITE)));
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, None), None);
    assert_eq!(
        range_step(&steps.step()),
        (base + STEP, 4 * MIB, Some(READ_WRITE))
    );
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, None), None);
    assert_eq!(
        range_step(&steps.step()),
        (base + 20 * MIB, 12 * MIB, Some(READ))
    );
    assert_eq!(
        steps.advance(DW_STATUS_SUCCESS, None),
        Some(DW_STATUS_BAD_STATE)
    );
}

#[test]
fn a_failed_unmap_step_is_retried_then_left_partial() {
    let base = 0x8000_0000;
    let request = NativeSyscallRequest::AddressRegionUnmap {
        address_region: REGION,
        address: DwUserAddress(base),
        byte_len: 2 * STEP,
    };
    let mut steps = Steps::new(request, STEP);
    assert_eq!(steps.snapshot_range(), None);
    assert_eq!(range_step(&steps.step()), (base, STEP, None));
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, None), None);
    for _ in 0..UNMAP_STEP_RETRIES {
        assert_eq!(steps.advance(DW_STATUS_BAD_STATE, None), None);
        assert_eq!(range_step(&steps.step()), (base + STEP, STEP, None));
    }
    assert_eq!(
        steps.advance(DW_STATUS_BAD_STATE, None),
        Some(DW_STATUS_BAD_STATE)
    );

    // A retry that succeeds finishes the call.
    let mut steps = Steps::new(request, STEP);
    assert_eq!(steps.advance(DW_STATUS_SUCCESS, None), None);
    assert_eq!(steps.advance(DW_STATUS_BAD_STATE, None), None);
    assert_eq!(
        steps.advance(DW_STATUS_SUCCESS, None),
        Some(DW_STATUS_SUCCESS)
    );
}
