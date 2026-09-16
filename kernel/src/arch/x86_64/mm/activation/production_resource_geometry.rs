//! WYR1-F production demand: the geometry a kernel that selects no guest test
//! must carry, as distinct from any selector's scenario demand.
//!
//! This is a source/host capacity model, not live acceptance.
//!
//! Every other capacity arm in `primordial.rs` keys off an evidence cfg, and
//! until DW1-F/WYR1-F F2A there was no cfg that meant "production". The
//! freestanding kernel therefore fell through to the bootstrap-era DW0 arm --
//! 3 Processes, 1 TaskGroup, 10 MemoryObjects, 10 leases, 32 RegistryObjects,
//! 3 Channel pairs, 4 wait registrations and a ten-handle table -- which is
//! the geometry of a product that launches `system/init` and nothing else. The
//! frozen WYR1-F graph is six roles beneath a three-level TaskGroup tree. It
//! does not fit, and nothing in the tree said so: the arm compiles, links and
//! produces an artifact that cannot instantiate its own product.
//!
//! That is the second instance of the defect `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md`
//! section 6 records. The first was the q35 IOAPIC bring-up reachable only
//! under three selector strings; F1A.2 closed it by emitting
//! `deepwyrm_dw1e_platform` for every freestanding build. This ledger closes
//! the second, and `DW1_WYR1_RUNTIME_RESET_IMPLEMENTATION_PLAN.md` section 10
//! is the rule both violated: a build must not silently inherit an unrelated
//! older capacity merely because no source constant was overridden.
//!
//! Topology comes from `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` section 1's frozen
//! spine and section 2's RRC-A membership, and from
//! `WYR1_C_DEVICE_HANDOFF_CONTRACT.md` section 4.1's TaskGroup tree as F1B
//! amended it. Image geometry comes from the exact F1B product: the six
//! resident images and `bin/hello` each have two PT_LOAD segments, the loader
//! owns one object per segment plus one stack object, and it unmaps its
//! scratch view before mapping the child.
//!
//! Recovery is production behaviour here, not a scenario: devmgr replacement,
//! registry replacement and shell restart are all reachable without a
//! selector, so the peaks below carry one replacement generation overlapping
//! the generation it replaces.

/// Enumerate every lifetime identity, including replaced generations. **This
/// census sizes no capacity** -- it records that the product was enumerated
/// rather than estimated. Every pool is sized from a *simultaneous* peak
/// instead, because the kernel's identity tables are occupancy bounds and a
/// finalized generation releases its slot. Treating a lifetime census as a
/// capacity is what selector 34's ledger records at `LIVE_IDENTITY_PEAK`, and
/// what selector 33's `fits` still does.
pub(super) const LIFETIME_IDENTITIES: [&str; 13] = [
    "primordial",
    "system-init",
    "registryd-1",
    "registryd-2",
    "devmgr-1",
    "devmgr-2",
    "uart16550d",
    "consoled-1",
    "consoled-2",
    "shell-1",
    "shell-2",
    "shell-job",
    "driver-attempt-2",
];

// init's own four authorities; registryd Process/TaskGroup/bootstrap/control;
// devmgr Process/bootstrap/publication; UART Process/bootstrap/control;
// consoled Process/bootstrap/registry/launch; shell Process/TaskGroup/job
// endpoint. Identical to selector 33's baseline because the resident set is
// the same six roles; the products differ after startup, not during it.
const INIT_RESIDENT_HANDLES: [usize; 6] = [4, 4, 3, 3, 4, 3];
pub(super) const INIT_BASELINE_HANDLES: usize = sum(&INIT_RESIDENT_HANDLES);

const RESIDENT_IMAGES: usize = 6;
const RESIDENT_IMAGE_OBJECTS: usize = 2 + 1; // PT_LOADs plus initial stack.
const JOB_IMAGE_OBJECTS: usize = 2 + 1; // `bin/hello` also has two PT_LOADs.
pub(super) const BASELINE_MEMORY: usize = RESIDENT_IMAGES * RESIDENT_IMAGE_OBJECTS + 1; // + bootfs.

/// A replacement generation is constructed before the generation it replaces
/// is reaped, so exactly one role is doubled at the peak. Init's recovery is
/// serialized per role, so this is one, not five.
const REPLACEMENT_GENERATIONS: usize = 1;
/// The foreground shell runs one job at a time. `ShellJobs` admits ordinary
/// jobs and cannot launch another shell, so a second concurrent job is not a
/// reachable state of this product.
const LIVE_SHELL_JOBS: usize = 1;

pub(super) const LIVE_PROCESSES: usize =
    RESIDENT_IMAGES + REPLACEMENT_GENERATIONS + LIVE_SHELL_JOBS;
/// The bootstrap root, the long-lived resource domain, and the driver-attempt
/// group that section 4.1 made a domain sibling rather than a generation
/// descendant -- the driver outlives a devmgr generation, so its group is not
/// accounted against that generation's identity.
const STRUCTURAL_TASK_GROUPS: usize = 3;
pub(super) const LIVE_TASK_GROUPS: usize = LIVE_PROCESSES + STRUCTURAL_TASK_GROUPS;

// Every pool indexed by identity -- Process, Thread, address space, region,
// region object, TaskGroup and execution thread -- is bounded by simultaneous
// occupancy, so the peak is the larger of the two live counts. Primordial is
// absent deliberately: it has retired before init launches its first role.
pub(super) const LIVE_IDENTITY_PEAK: usize = if LIVE_PROCESSES > LIVE_TASK_GROUPS {
    LIVE_PROCESSES
} else {
    LIVE_TASK_GROUPS
};

/// Loader stages are additive to the caller's existing handles and one new
/// attempt TaskGroup. Stream INIT staging retains at most three transferred
/// endpoints. Scratch memory closes before ThreadCreate. ChannelReduce briefly
/// needs the broad and reduced parent handles together with the child endpoint.
const STREAM_JOB_LOADER_HANDLES: usize = 1 + 3 + 1 + 2 + 1;
/// A devmgr replacement duplicates the resource-domain handle with sender-side
/// rights, holds the reduced handle it will MOVE, and retains the outgoing
/// generation's Process until it is reaped.
const REPLACEMENT_STAGING_HANDLES: usize = 3;
pub(super) const HANDLE_PEAK: usize =
    INIT_BASELINE_HANDLES + STREAM_JOB_LOADER_HANDLES + REPLACEMENT_STAGING_HANDLES;
pub(super) const MEMORY_PEAK: usize = BASELINE_MEMORY
    + REPLACEMENT_GENERATIONS * RESIDENT_IMAGE_OBJECTS
    + LIVE_SHELL_JOBS * JOB_IMAGE_OBJECTS
    + 1; // Loader scratch view, open until the child mapping is installed.
pub(super) const MAPPING_PEAK: usize = MEMORY_PEAK;

/// Selector 33's baseline for this identical resident set: primordial->init,
/// init's five role startups, the service pairs to registryd, devmgr's
/// publication pair, the device control pair, consoled's launch pair and the
/// shell's job-control pair.
pub(super) const BASELINE_CHANNEL_PAIRS: usize = 17;
/// A replacement generation brings its startup, control and publication pairs
/// before the outgoing generation's peers have closed.
const REPLACEMENT_CHANNEL_PAIRS: usize = 3;
/// Three stream pairs and one startup pair per live job.
const JOB_CHANNEL_PAIRS: usize = 3 + 1;
pub(super) const CHANNEL_PAIR_PEAK: usize =
    BASELINE_CHANNEL_PAIRS + REPLACEMENT_CHANNEL_PAIRS + LIVE_SHELL_JOBS * JOB_CHANNEL_PAIRS;
/// Conservative: both endpoints of every pair above are charged, rather than
/// assuming any particular peer has already observed close.
pub(super) const CHANNEL_ENDPOINT_PEAK: usize = 2 * CHANNEL_PAIR_PEAK;

/// devmgr owns the boot resource domain; the driver holds the one UART
/// DeviceResource and its one Interrupt.
const DEVICE_RESOURCES: usize = 1;
const INTERRUPTS: usize = 1;
/// The UART pacing Timer and init's resident control tick can overlap.
pub(super) const TIMER_PEAK: usize = 2;
pub(super) const EVENT_PEAK: usize = 0;
pub(super) const REGION_MAPPING_PEAK: usize = 2 + 1 + 1 + 1; // PT_LOADs, stack, bootfs, scratch.

pub(super) const REGISTRY_PEAK: usize = LIVE_PROCESSES * 3 // Process, Thread, root
    + LIVE_TASK_GROUPS
    + MEMORY_PEAK
    + CHANNEL_ENDPOINT_PEAK
    + DEVICE_RESOURCES
    + INTERRUPTS
    + TIMER_PEAK;

// Not re-derived. `wyr1e_wait_geometry` already models this exact six-role
// interactive graph, and its non-E8 arm is 12 + 3 + 4 + 6 + 7 + 7 = 39: the
// controller's resident supervision set, the registry, device, console, shell
// and job sets. An independent enumeration here first reached 32, which is not
// a smaller graph -- it is the same graph with rows missed. Two decompositions
// of one topology disagreeing means the lower one is wrong, so this takes the
// established model rather than competing with it.
//
// Reconcile here if that ledger's arm moves. The two cannot be linked by a
// `const` because `wyr1e_wait_geometry` compiles only under the selector that
// needs it, which is the same reason selector 34's ledger restates E8's
// figures instead of importing them.
pub(super) const INTERACTIVE_GRAPH_WAITS: usize = 12 + 3 + 4 + 6 + 7 + 7;
/// What this product adds to that graph: an exit wait apiece for the live job
/// and the replacement generation, each owning a Channel and a Process
/// registration.
const ADDED_EXIT_WAITS: usize = (LIVE_SHELL_JOBS + REPLACEMENT_GENERATIONS) * 2;
pub(super) const WAIT_PEAK: usize = INTERACTIVE_GRAPH_WAITS + ADDED_EXIT_WAITS;

// Wyrmroot owns the archive parser, whose selected record limit is 4096.
// Reconciled against the built archive, 2026-09-16 (`f1b/normal-01`,
// `artifacts/bootfs.img`): the six role executables, five bootstrap
// configuration entries -- launch policy, `rrc-a-v1`, `wyr1-a-gate-v1`, the
// WYR1-C device manifest and `wyr1-c-gate-v1` -- and `bin/hello`. No extra
// kernel object is made per entry.
pub(super) const BOOTFS_ENTRY_PEAK: usize = 6 + 5 + 1;
pub(super) const BOOTFS_ENTRY_CAPACITY: usize = 4096;

/// The production product produces no evidence records. The collector is
/// `test-support`-gated and is not compiled into this kernel at all, so the
/// selected evidence capacity is zero rather than an unused positive number
/// that would look like an unexercised budget.
pub(super) const EVIDENCE_PEAK: usize = 0;

const fn sum(values: &[usize]) -> usize {
    let mut result = 0;
    let mut index = 0;
    while index < values.len() {
        result += values[index];
        index += 1;
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Capacity {
    pub handles: usize,
    pub memory: usize,
    pub mappings: usize,
    /// Simultaneous identity capacity, **not** a lifetime count. It becomes
    /// `THREADS`, and a `THREADS` above the linked thread-stack arena makes
    /// thread creation statically impossible; see the assertion below.
    pub identities: usize,
    pub registry: usize,
    pub channel_pairs: usize,
    pub waits: usize,
    pub evidence: usize,
}

// PRODUCTION_SELECTED_CAPACITIES per_process_handle_capacity=48 memory_object_capacity=48 mapping_lease_capacity=48 registry_object_capacity=160
pub(super) const SELECTED: Capacity = Capacity {
    handles: 48,
    memory: 48,
    mappings: 48,
    identities: 16,
    registry: 160,
    channel_pairs: 32,
    waits: 48,
    evidence: 0,
};

pub(super) const fn fits(capacity: Capacity) -> bool {
    capacity.handles >= HANDLE_PEAK
        && capacity.memory >= MEMORY_PEAK
        && capacity.mappings >= MAPPING_PEAK
        && capacity.identities >= LIVE_IDENTITY_PEAK
        && capacity.registry >= REGISTRY_PEAK
        && capacity.channel_pairs >= CHANNEL_PAIR_PEAK
        && capacity.waits >= WAIT_PEAK
        // Equality, not `>=`. Every other bound is a floor, but a production
        // build with a nonzero evidence capacity has inherited a selector's
        // collector rather than satisfied a demand, so the check must reject
        // above as well as below.
        && capacity.evidence == EVIDENCE_PEAK
}

const _: () = assert!(fits(SELECTED));
// `identities` becomes `THREADS`, and every Thread needs one of the linked
// per-thread kernel stacks. Selecting more Threads than the arena has stacks
// does not fail a bounds check at run time: it makes thread creation
// unsatisfiable for constants the optimizer can see, so a release build folds
// `primordial::enter` to a panic, `--gc-sections` drops every subsystem the
// folded continuation no longer reaches, and the artifact boots no product at
// all. That is the failure selector 34 measured at R1C. The production arena
// is the ordinary sixteen and this ledger selects exactly sixteen, so the
// relation holds with no margin -- a seventeenth identity must raise the arena
// deliberately, not arrive by edit.
const _: () = assert!(SELECTED.identities <= crate::memory::kernel_stack::E3_THREAD_STACK_COUNT);
// Deliberately below selector 33's 64-handle tables, matching selector 34's
// choice for the same reason: E8's widened per-Process pools are why its
// termination requirement was 3,014,752 bytes, and this product's demand does
// not require them.
const _: () = assert!(SELECTED.handles < 64);
// The production product carries no evidence collector. If `test-support` is
// ever admitted into a production build this ledger must be revisited rather
// than silently inheriting a selector's record capacity.
const _: () = assert!(SELECTED.evidence == 0);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn production_selected_marker_matches_executable_capacities() {
        let marker = std::format!(
            "// PRODUCTION_SELECTED_CAPACITIES per_process_handle_capacity={} memory_object_capacity={} mapping_lease_capacity={} registry_object_capacity={}",
            SELECTED.handles,
            SELECTED.memory,
            SELECTED.mappings,
            SELECTED.registry,
        );
        assert_eq!(
            include_str!("production_resource_geometry.rs")
                .lines()
                .filter(|line| *line == marker)
                .count(),
            1
        );
    }

    #[test]
    fn the_selected_capacities_are_the_numbers_the_f_receipt_binds() {
        // Wyrmroot's `tools/xtask/src/wyr1f.rs` writes these into every WYR1-F
        // freeze receipt as `kernel_identity_capacity`,
        // `kernel_handle_capacity`, `kernel_registry_capacity` and
        // `kernel_thread_stack_count`. It cannot read them from here, so this
        // is the reconciliation: a capacity change fails in this repository
        // before it can reach a product whose receipt still claims the old
        // figure.
        assert_eq!(SELECTED.identities, 16);
        assert_eq!(SELECTED.handles, 48);
        assert_eq!(SELECTED.registry, 160);
        assert_eq!(crate::memory::kernel_stack::E3_THREAD_STACK_COUNT, 16);
    }

    #[test]
    fn production_peaks_are_the_documented_arithmetic() {
        assert_eq!(INIT_BASELINE_HANDLES, 21);
        assert_eq!(STREAM_JOB_LOADER_HANDLES, 8);
        assert_eq!(HANDLE_PEAK, 32);
        assert_eq!(BASELINE_MEMORY, 19);
        assert_eq!(MEMORY_PEAK, 26);
        assert_eq!(MAPPING_PEAK, 26);
        assert_eq!(LIVE_PROCESSES, 8);
        assert_eq!(LIVE_TASK_GROUPS, 11);
        assert_eq!(LIVE_IDENTITY_PEAK, 11);
        assert_eq!(CHANNEL_PAIR_PEAK, 24);
        assert_eq!(CHANNEL_ENDPOINT_PEAK, 48);
        assert_eq!(REGISTRY_PEAK, 113);
        assert_eq!(INTERACTIVE_GRAPH_WAITS, 39);
        assert_eq!(WAIT_PEAK, 43);
        assert_eq!(BOOTFS_ENTRY_PEAK, 12);
    }

    #[test]
    fn the_bootstrap_era_geometry_does_not_fit_this_product() {
        // The arm the production kernel used before F2A: the DW0 shape that
        // launches `system/init` and nothing else. Recorded as an executable
        // fact so that reverting the wiring fails here rather than producing
        // an artifact that cannot instantiate its own product.
        let bootstrap_era = Capacity {
            handles: 10,
            memory: 10,
            mappings: 10,
            identities: 3,
            registry: 32,
            channel_pairs: 3,
            waits: 4,
            evidence: 0,
        };
        assert!(!fits(bootstrap_era));
        assert!(bootstrap_era.identities < LIVE_IDENTITY_PEAK);
        assert!(bootstrap_era.registry < REGISTRY_PEAK);
        assert!(bootstrap_era.waits < WAIT_PEAK);
        assert!(bootstrap_era.channel_pairs < CHANNEL_PAIR_PEAK);
    }

    #[test]
    fn the_lifetime_census_is_not_used_as_a_capacity() {
        // Thirteen lifetime identities, eleven simultaneous. The census is
        // larger than every pool it could be mistaken for, which is why it is
        // absent from `fits`.
        assert!(LIFETIME_IDENTITIES.len() > LIVE_IDENTITY_PEAK);
        assert!(fits(Capacity {
            identities: LIVE_IDENTITY_PEAK,
            ..SELECTED
        }));
    }

    #[test]
    fn the_selected_evidence_capacity_is_absent_not_inherited() {
        assert_eq!(EVIDENCE_PEAK, 0);
        assert_eq!(SELECTED.evidence, 0);
    }
}
