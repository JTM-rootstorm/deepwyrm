//! The per-CPU runtime facts other CPUs read under the runtime authority
//! (S2K-6, design §11.1).
//!
//! Each CPU's slot is the single source of its remotely read facts. Only the
//! CPU that owns a slot may mutate it: [`CpuSlots::split`] hands out the one
//! `&mut` slot only for a [`CpuOwner`], and every other slot only behind a
//! shared reference ([`OtherCpus`]). Owners are minted once, one per CPU, and
//! are neither `Clone` nor constructible outside this module, so a CPU that
//! does not own a slot has no way to name it mutably. The one remote write a
//! slot type accepts is its [`RemotelyStaged`] operation, reached only through
//! [`OtherCpus::stage_remote`].
//!
//! Generic over the slot type so the host build compiles it and the
//! compile-fail cases in `kernel/tests/root_switch_ui.rs` hold these properties
//! statically. `primordial.rs` binds the live slot type.

#![cfg_attr(
    test,
    allow(
        dead_code,
        reason = "the carrier that owns the slots is target-only; host tests and the compile-fail cases exercise the types"
    )
)]

use crate::cpu::CpuIndex;

/// The right to mutate one CPU's slot. One per CPU, minted once by
/// [`CpuSlots::mint_owners`]; neither `Clone` nor `Copy`, and its field is
/// private, so no other code can build one.
pub(super) struct CpuOwner {
    cpu: CpuIndex,
}

impl CpuOwner {
    pub(super) const fn cpu(&self) -> CpuIndex {
        self.cpu
    }
}

/// A slot type's one remote write: the operation another CPU may perform on
/// a slot it does not own, under the same runtime authority.
pub(super) trait RemotelyStaged {
    type Staged;

    fn stage_remote(&mut self, staged: Self::Staged);
}

pub(super) struct CpuSlots<S, const N: usize> {
    slots: [S; N],
    owners_minted: bool,
}

impl<S, const N: usize> CpuSlots<S, N> {
    pub(super) const fn new(slots: [S; N]) -> Self {
        Self {
            slots,
            owners_minted: false,
        }
    }

    /// Mints every slot's owner, once.
    pub(super) fn mint_owners(&mut self) -> [CpuOwner; N] {
        assert!(!self.owners_minted, "CPU slot owners were minted twice");
        self.owners_minted = true;
        core::array::from_fn(|index| CpuOwner {
            cpu: CpuIndex::new(index).unwrap_or_else(|| panic!("CPU slot {index} out of range")),
        })
    }

    /// The owner's slot, mutably, and every other slot read-only.
    pub(super) fn split(&mut self, owner: &CpuOwner) -> (&mut S, OtherCpus<'_, S>) {
        let index = owner.cpu.index();
        let (before, rest) = self.slots.split_at_mut(index);
        let (own, after) = rest
            .split_first_mut()
            .unwrap_or_else(|| panic!("CPU slot {index} out of range"));
        (
            own,
            OtherCpus {
                before,
                after,
                own: index,
            },
        )
    }
}

/// Every slot but the owner's: readable, and writable only through the slot
/// type's [`RemotelyStaged`] operation.
pub(super) struct OtherCpus<'a, S> {
    before: &'a mut [S],
    after: &'a mut [S],
    own: usize,
}

impl<S> OtherCpus<'_, S> {
    /// Another CPU's slot. `None` for the owner's own CPU, which is not here.
    pub(super) fn get(&self, cpu: CpuIndex) -> Option<&S> {
        let index = cpu.index();
        if index < self.own {
            self.before.get(index)
        } else if index > self.own {
            self.after.get(index - self.own - 1)
        } else {
            None
        }
    }

    /// Every slot in CPU order, with the owner's own slot in its place.
    pub(super) fn with_own<'s>(&'s self, own: &'s S) -> impl Iterator<Item = &'s S> {
        self.before
            .iter()
            .chain(core::iter::once(own))
            .chain(self.after.iter())
    }
}

impl<S: RemotelyStaged> OtherCpus<'_, S> {
    /// The one remote write: stages `staged` in another CPU's slot.
    pub(super) fn stage_remote(&mut self, cpu: CpuIndex, staged: S::Staged) {
        let index = cpu.index();
        let slot = if index < self.own {
            self.before.get_mut(index)
        } else if index > self.own {
            self.after.get_mut(index - self.own - 1)
        } else {
            None
        };
        slot.unwrap_or_else(|| panic!("remote staging named the owner's CPU or no CPU"))
            .stage_remote(staged);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[derive(Debug, Default, PartialEq)]
    struct Slot {
        value: u32,
        staged: Option<u32>,
    }

    impl RemotelyStaged for Slot {
        type Staged = u32;

        fn stage_remote(&mut self, staged: u32) {
            assert!(self.staged.replace(staged).is_none());
        }
    }

    fn cpu(index: usize) -> CpuIndex {
        CpuIndex::new(index).unwrap()
    }

    #[test]
    fn the_owner_mutates_its_own_slot_and_reads_the_others_in_cpu_order() {
        let mut slots = CpuSlots::new(core::array::from_fn::<_, 4, _>(|index| Slot {
            value: index as u32,
            staged: None,
        }));
        let owners = slots.mint_owners();
        assert_eq!(
            owners.each_ref().map(|owner| owner.cpu().index()),
            [0, 1, 2, 3]
        );
        let (own, others) = slots.split(&owners[2]);
        own.value = 20;
        assert!(others.get(cpu(2)).is_none());
        assert_eq!(others.get(cpu(3)).map(|slot| slot.value), Some(3));
        assert_eq!(
            others
                .with_own(own)
                .map(|slot| slot.value)
                .collect::<std::vec::Vec<_>>(),
            [0, 1, 20, 3]
        );
    }

    #[test]
    fn the_remote_write_reaches_only_another_cpus_slot() {
        let mut slots = CpuSlots::new(core::array::from_fn::<_, 4, _>(|_| Slot::default()));
        let owners = slots.mint_owners();
        let (_, mut others) = slots.split(&owners[1]);
        others.stage_remote(cpu(0), 7);
        others.stage_remote(cpu(3), 9);
        assert_eq!(others.get(cpu(0)).and_then(|slot| slot.staged), Some(7));
        assert_eq!(others.get(cpu(3)).and_then(|slot| slot.staged), Some(9));
        let own = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            others.stage_remote(cpu(1), 1);
        }));
        assert!(own.is_err());
    }

    #[test]
    fn owners_are_minted_once() {
        let mut slots = CpuSlots::new(core::array::from_fn::<_, 2, _>(|_| Slot::default()));
        let _owners = slots.mint_owners();
        let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = slots.mint_owners();
        }));
        assert!(again.is_err());
    }
}
