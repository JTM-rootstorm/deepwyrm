//! Kernel-private logical CPU identity shared by SMP ownership models.
//!
//! `CpuIndex` is bounded by the canonical DW0-H topology. It is never exposed
//! through the userspace ABI, and raw firmware/APIC identifiers must be
//! resolved through the architecture CPU registry before constructing it.

/// Canonical DW0-H logical CPU capacity.
pub(crate) const CPU_CAPACITY: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuIndex(u8);

impl CpuIndex {
    pub(crate) const BOOTSTRAP: Self = Self(0);

    pub(crate) const fn new(index: usize) -> Option<Self> {
        if index < CPU_CAPACITY {
            Some(Self(index as u8))
        } else {
            None
        }
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_cpu_index_is_bounded_and_bootstrap_is_zero() {
        assert_eq!(CpuIndex::BOOTSTRAP.index(), 0);
        for index in 0..CPU_CAPACITY {
            assert_eq!(CpuIndex::new(index).map(CpuIndex::index), Some(index));
        }
        assert_eq!(CpuIndex::new(CPU_CAPACITY), None);
    }
}
