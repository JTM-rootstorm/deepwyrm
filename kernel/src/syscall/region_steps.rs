//! A family-G call made in steps (DW2 M4b, plan §7.2).
//!
//! An `AddressRegionMap`, `Unmap` or `Protect` larger than one step is a
//! chain of ordinary family-G transactions, one step each, with a safe point
//! between them, so the global locks are never held for more than one step.
//! Pieces of one mapping merge in the model, so the chain ends with the
//! slots and leases one call would leave. This module is the chain's plan:
//! which step comes next, and what to do when one fails.
//!
//! - A failed map unmaps the steps it made; a failed protect restores the
//!   protections it changed, from a snapshot taken before its first step.
//! - An unmap or protect checks the whole range (in the region, wholly
//!   mapped) before its first step, so a gap refuses it before any change.
//! - A failed unmap step is retried, each attempt after a safe point; when
//!   the retries run out the call returns the error with the steps already
//!   made left unmapped. After the whole-range check only a transient pin
//!   or a concurrent change can fail a step.
//! - A step that fails before anything changed returns its status at once.
//! - The undo is best effort: an undo step that fails is skipped.

use super::native::NativeSyscallRequest;
use deepwyrm_abi::{
    DW_ADDRESS_REGION_MAP_FLAG_FIXED, DW_STATUS_SUCCESS, DwAddressRegionMapArgsV1, DwStatus,
    DwUserAddress,
};

const PAGE_SIZE: u64 = 4096;

/// The protections over a range, as (start, length, protection) pieces.
pub(crate) type RangeSnapshot<const SLOTS: usize> = [Option<(u64, u64, u32)>; SLOTS];

/// Failed unmap steps retried in one call.
pub(crate) const UNMAP_STEP_RETRIES: usize = 4;

/// One step's map input: its arguments, its protection, and the room its
/// placement must find, or the status that fails it before any step.
pub(crate) type MapStep<P> = Result<(DwAddressRegionMapArgsV1, P, u64), DwStatus>;

/// The next step: the request to run, the map input if it is a map step,
/// and whether the syscall returns from it.
pub(crate) struct Step<P> {
    pub(crate) request: NativeSyscallRequest,
    pub(crate) map: Option<MapStep<P>>,
    pub(crate) last: bool,
}

#[derive(Clone, Copy)]
enum Kind<P> {
    /// A map whose arguments are not yet copied in.
    MapPending,
    /// A map refused before any step.
    MapRefused(DwStatus),
    Map {
        args: DwAddressRegionMapArgsV1,
        protection: P,
    },
    Unmap,
    Protect(u32),
}

/// A range the undo restores: unmapped (`None`) or reprotected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UndoPiece {
    start: u64,
    byte_len: u64,
    protection: Option<u32>,
}

enum Progress<const SLOTS: usize> {
    Forward,
    Undo {
        status: DwStatus,
        pieces: [Option<UndoPiece>; SLOTS],
        piece: usize,
        done: u64,
    },
}

pub(crate) struct RegionSteps<P, const SLOTS: usize> {
    request: NativeSyscallRequest,
    step_bytes: u64,
    kind: Kind<P>,
    start: u64,
    total: u64,
    done: u64,
    /// A map's address, once known.
    placed: Option<u64>,
    /// A protect's old protections over its range.
    snapshot: Option<RangeSnapshot<SLOTS>>,
    retries: usize,
    progress: Progress<SLOTS>,
}

impl<P: Copy, const SLOTS: usize> RegionSteps<P, SLOTS> {
    /// The plan for a family-G `request`, in steps of `step_bytes`.
    #[allow(
        clippy::wildcard_enum_match_arm,
        reason = "every request other than an unmap or protect starts as a pending map"
    )]
    pub(crate) fn new(request: NativeSyscallRequest, step_bytes: u64) -> Self {
        let (kind, start, total) = match request {
            NativeSyscallRequest::AddressRegionUnmap {
                address, byte_len, ..
            } => (Kind::Unmap, address.0, byte_len),
            NativeSyscallRequest::AddressRegionProtect {
                address,
                byte_len,
                protections,
                ..
            } => (Kind::Protect(protections), address.0, byte_len),
            _ => (Kind::MapPending, 0, 0),
        };
        Self {
            request,
            step_bytes,
            kind,
            start,
            total,
            done: 0,
            placed: None,
            snapshot: None,
            retries: UNMAP_STEP_RETRIES,
            progress: Progress::Forward,
        }
    }

    /// Whether the map's arguments are still to be copied in.
    pub(crate) fn needs_map_input(&self) -> bool {
        matches!(self.kind, Kind::MapPending)
    }

    /// The map's copied-in arguments, or the status refusing them.
    pub(crate) fn set_map_input(&mut self, input: Result<(DwAddressRegionMapArgsV1, P), DwStatus>) {
        self.kind = match input {
            Ok((args, protection)) => {
                self.total = args.byte_len.0;
                if args.flags.0 == DW_ADDRESS_REGION_MAP_FLAG_FIXED.0 {
                    self.start = args.requested_address.0;
                    self.placed = Some(self.start);
                }
                Kind::Map { args, protection }
            }
            Err(status) => Kind::MapRefused(status),
        };
    }

    /// Whether the call takes more than one step. A call that is not
    /// page-aligned, or whose range overflows, runs as one step, which
    /// refuses it as it always has.
    pub(crate) fn in_steps(&self) -> bool {
        let aligned = match self.kind {
            Kind::Map { args, .. } => {
                args.memory_object_offset.0.is_multiple_of(PAGE_SIZE)
                    && args
                        .memory_object_offset
                        .0
                        .checked_add(self.total)
                        .is_some()
            }
            Kind::Unmap | Kind::Protect(_) => true,
            Kind::MapPending | Kind::MapRefused(_) => return false,
        };
        aligned
            && self.total > self.step_bytes
            && self.total.is_multiple_of(PAGE_SIZE)
            && self.start.is_multiple_of(PAGE_SIZE)
            && self.start.checked_add(self.total).is_some()
    }

    /// The range an unmap or protect in steps checks whole, and snapshots,
    /// before its first step, as (region handle, start, end).
    #[allow(
        clippy::wildcard_enum_match_arm,
        reason = "only an unmap or protect takes a range snapshot"
    )]
    pub(crate) fn snapshot_range(&self) -> Option<(deepwyrm_abi::DwHandle, u64, u64)> {
        match self.request {
            NativeSyscallRequest::AddressRegionUnmap { address_region, .. }
            | NativeSyscallRequest::AddressRegionProtect { address_region, .. }
                if self.snapshot.is_none() && self.done == 0 && self.in_steps() =>
            {
                Some((address_region, self.start, self.start + self.total))
            }
            _ => None,
        }
    }

    /// The whole-range check and the protections over the range. `Err`:
    /// the call is refused with that status before any step, as one call
    /// would be (review D1: a gap must not leave a partial unmap).
    pub(crate) fn set_snapshot(
        &mut self,
        snapshot: Result<RangeSnapshot<SLOTS>, DwStatus>,
    ) -> Result<(), DwStatus> {
        self.snapshot = Some(snapshot?);
        Ok(())
    }

    /// A map's address: where its first step placed it.
    pub(crate) fn address(&self) -> Option<u64> {
        self.placed
    }

    /// The step to run next.
    pub(crate) fn step(&self) -> Step<P> {
        if !self.in_steps() {
            let map = match self.kind {
                Kind::Map { args, protection } => Some(Ok((args, protection, args.byte_len.0))),
                Kind::MapRefused(status) => Some(Err(status)),
                Kind::MapPending | Kind::Unmap | Kind::Protect(_) => None,
            };
            return Step {
                request: self.request,
                map,
                last: true,
            };
        }
        match &self.progress {
            Progress::Forward => {
                let chunk = self.step_bytes.min(self.total - self.done);
                self.forward_step(chunk)
            }
            Progress::Undo {
                pieces,
                piece,
                done,
                ..
            } => {
                let piece = pieces[*piece].expect("an undo in progress has a current piece");
                let chunk = self.step_bytes.min(piece.byte_len - done);
                let address = DwUserAddress(piece.start + done);
                let request = match (piece.protection, self.request) {
                    (None, NativeSyscallRequest::AddressRegionMap { address_region, .. }) => {
                        NativeSyscallRequest::AddressRegionUnmap {
                            address_region,
                            address,
                            byte_len: chunk,
                        }
                    }
                    (
                        Some(protections),
                        NativeSyscallRequest::AddressRegionProtect { address_region, .. },
                    ) => NativeSyscallRequest::AddressRegionProtect {
                        address_region,
                        address,
                        byte_len: chunk,
                        protections,
                    },
                    _ => unreachable!("only a map or a protect is undone"),
                };
                Step {
                    request,
                    map: None,
                    last: false,
                }
            }
        }
    }

    fn forward_step(&self, chunk: u64) -> Step<P> {
        let address = DwUserAddress(self.start + self.done);
        let (request, map) = match (self.kind, self.request) {
            (Kind::Map { args, protection }, request) => {
                let mut step = args;
                step.byte_len.0 = chunk;
                step.memory_object_offset.0 = args.memory_object_offset.0 + self.done;
                let room = match self.placed {
                    Some(placed) => {
                        step.flags = DW_ADDRESS_REGION_MAP_FLAG_FIXED;
                        step.requested_address = DwUserAddress(placed + self.done);
                        chunk
                    }
                    // The first step of an allocator-placed map finds room
                    // for all of it.
                    None => self.total,
                };
                (request, Some(Ok((step, protection, room))))
            }
            (Kind::Unmap, NativeSyscallRequest::AddressRegionUnmap { address_region, .. }) => (
                NativeSyscallRequest::AddressRegionUnmap {
                    address_region,
                    address,
                    byte_len: chunk,
                },
                None,
            ),
            (
                Kind::Protect(protections),
                NativeSyscallRequest::AddressRegionProtect { address_region, .. },
            ) => (
                NativeSyscallRequest::AddressRegionProtect {
                    address_region,
                    address,
                    byte_len: chunk,
                    protections,
                },
                None,
            ),
            _ => unreachable!("a call in steps is a map, an unmap or a protect"),
        };
        Step {
            request,
            map,
            last: false,
        }
    }

    /// Records a step's result (`address`: where a map step placed its
    /// piece). `Some(status)` when the call is finished and returns it.
    pub(crate) fn advance(&mut self, status: DwStatus, address: Option<u64>) -> Option<DwStatus> {
        match &mut self.progress {
            Progress::Forward => {
                if status != DW_STATUS_SUCCESS {
                    return self.forward_failed(status);
                }
                if matches!(self.kind, Kind::Map { .. }) && self.placed.is_none() {
                    let placed = address.expect("a successful map step has an address");
                    self.placed = Some(placed);
                    self.start = placed;
                }
                self.done += self.step_bytes.min(self.total - self.done);
                (self.done == self.total).then_some(DW_STATUS_SUCCESS)
            }
            Progress::Undo {
                status: failed,
                pieces,
                piece,
                done,
            } => {
                let current = pieces[*piece].expect("an undo in progress has a current piece");
                *done += self.step_bytes.min(current.byte_len - *done);
                if *done == current.byte_len {
                    *piece += 1;
                    *done = 0;
                }
                (pieces.get(*piece).copied().flatten().is_none()).then_some(*failed)
            }
        }
    }

    fn forward_failed(&mut self, status: DwStatus) -> Option<DwStatus> {
        if self.done == 0 {
            return Some(status);
        }
        let mut pieces = [None; SLOTS];
        match self.kind {
            Kind::Unmap => {
                if self.retries == 0 {
                    return Some(status);
                }
                self.retries -= 1;
                return None;
            }
            Kind::Map { .. } => {
                pieces[0] = Some(UndoPiece {
                    start: self.start,
                    byte_len: self.done,
                    protection: None,
                });
            }
            Kind::Protect(_) => {
                let end = self.start + self.done;
                let mut count = 0;
                for (start, byte_len, protection) in
                    self.snapshot.iter().flatten().flatten().copied()
                {
                    let piece_start = start.max(self.start);
                    let piece_end = (start + byte_len).min(end);
                    if piece_start < piece_end {
                        pieces[count] = Some(UndoPiece {
                            start: piece_start,
                            byte_len: piece_end - piece_start,
                            protection: Some(protection),
                        });
                        count += 1;
                    }
                }
            }
            Kind::MapPending | Kind::MapRefused(_) => return Some(status),
        }
        if pieces[0].is_none() {
            return Some(status);
        }
        self.progress = Progress::Undo {
            status,
            pieces,
            piece: 0,
            done: 0,
        };
        None
    }
}

#[cfg(test)]
#[path = "region_steps/tests.rs"]
mod tests;
