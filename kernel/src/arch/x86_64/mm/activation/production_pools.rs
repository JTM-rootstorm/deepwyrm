//! The production kernel's pool capacities, built from
//! `arch/x86_64/pools.toml` (root `OS_STACK_ARCHITECTURE_PLAN.md` C1).
//!
//! These were once a ledger of Wyrmroot's roles, so a new service was a
//! kernel edit. The kernel now holds only its capacities and reports them
//! through `kernel_get_limits`; Wyrmroot's product build reads the same file
//! from the paired checkout and refuses a product whose demand does not fit.

pub(super) const HANDLES_PER_PROCESS: usize = pool(env!("DEEPWYRM_POOL_HANDLES_PER_PROCESS"));
/// Processes, Threads, TaskGroups and address spaces each, until C3 splits
/// them. The build refuses more than the kernel-stack arena holds.
pub(super) const IDENTITIES: usize = pool(env!("DEEPWYRM_POOL_IDENTITIES"));
pub(super) const REGISTRY_OBJECTS: usize = pool(env!("DEEPWYRM_POOL_REGISTRY_OBJECTS"));
pub(super) const MEMORY_OBJECTS: usize = pool(env!("DEEPWYRM_POOL_MEMORY_OBJECTS"));
pub(super) const MAPPING_LEASES: usize = pool(env!("DEEPWYRM_POOL_MAPPING_LEASES"));
pub(super) const REGION_SLOTS: usize = pool(env!("DEEPWYRM_POOL_REGION_SLOTS"));
pub(super) const CHANNEL_PAIRS: usize = pool(env!("DEEPWYRM_POOL_CHANNEL_PAIRS"));
pub(super) const CHANNEL_DEPTH: usize = pool(env!("DEEPWYRM_POOL_CHANNEL_DEPTH"));
pub(super) const WAIT_REGISTRATIONS: usize = pool(env!("DEEPWYRM_POOL_WAIT_REGISTRATIONS"));
pub(super) const TIMERS: usize = pool(env!("DEEPWYRM_POOL_TIMERS"));
pub(super) const EVENTS: usize = pool(env!("DEEPWYRM_POOL_EVENTS"));

/// A build-script value: decimal, nonzero, and a 32-bit count (the build
/// script refuses anything else before this runs).
const fn pool(value: &str) -> usize {
    let bytes = value.as_bytes();
    assert!(!bytes.is_empty(), "build-generated pool value is empty");
    let mut index = 0;
    let mut output = 0_usize;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(
            digit.is_ascii_digit(),
            "build-generated pool value is not decimal"
        );
        output = output * 10 + (digit - b'0') as usize;
        assert!(output <= u32::MAX as usize, "pool value exceeds 32 bits");
        index += 1;
    }
    output
}

// Every Thread needs one of the linked per-thread kernel stacks. Selecting more
// Threads than the arena has stacks does not fail a bounds check at run time:
// it makes thread creation unsatisfiable for constants the optimizer can see,
// so a release build folds `primordial::enter` to a panic and the artifact
// boots nothing (selector 34 at R1C). The build script refuses it too.
const _: () = assert!(IDENTITIES <= crate::memory::kernel_stack::E3_THREAD_STACK_COUNT);

#[cfg(test)]
mod tests {
    use super::pool;

    #[test]
    fn pool_values_parse_as_decimal_counts() {
        assert_eq!(pool("96"), 96);
        assert_eq!(pool("4294967295"), u32::MAX as usize);
    }

    #[test]
    #[should_panic(expected = "not decimal")]
    fn a_pool_value_with_a_sign_is_refused() {
        pool("-1");
    }

    #[test]
    #[should_panic(expected = "exceeds 32 bits")]
    fn a_pool_value_past_32_bits_is_refused() {
        pool("4294967296");
    }
}
