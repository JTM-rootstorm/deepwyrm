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
//!
//! The storage spine (root `STORAGE_PLAN.md` W2-W7) adds seven resident
//! roles beneath init: a `virtio-blkd` per disk (boot and data), a `blockmgr`
//! per volume (boot and root), `fat32d`, `ext4d` and `vfsd`. W2-W6 added four
//! of them without this ledger, and the product kept fitting only by slack;
//! the data disk's driver (W7) was the role that stopped fitting, and the
//! product booted no shell. The storage rows below are that enumeration.

/// Enumerate every lifetime identity, including replaced generations. **This
/// census sizes no capacity** -- it records that the product was enumerated
/// rather than estimated. Every pool is sized from a *simultaneous* peak
/// instead, because the kernel's identity tables are occupancy bounds and a
/// finalized generation releases its slot. Treating a lifetime census as a
/// capacity is what selector 34's ledger records at `LIVE_IDENTITY_PEAK`, and
/// what selector 33's `fits` still does.
pub(super) const LIFETIME_IDENTITIES: [&str; 23] = [
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
    "shell-job-1",
    "shell-job-2",
    "shell-job-3",
    "shell-job-4",
    "driver-attempt-2",
    "virtio-blkd-boot",
    "virtio-blkd-data",
    "blockmgr-boot",
    "blockmgr-root",
    "fat32d",
    "ext4d",
    "vfsd",
];

// init's own four authorities; registryd Process/TaskGroup/bootstrap/control;
// devmgr Process/bootstrap/publication; UART Process/bootstrap/control;
// consoled Process/bootstrap/registry/launch; shell Process/TaskGroup/job
// endpoint. Identical to selector 33's baseline because the resident set is
// the same six roles; the products differ after startup, not during it.
const INIT_RESIDENT_HANDLES: [usize; 6] = [4, 4, 3, 3, 4, 3];
/// Init holds each disk driver's Process, launch Channel and TaskGroup, and
/// each storage service's Process, launch Channel, TaskGroup and control
/// Channel.
const STORAGE_DRIVERS: usize = 2;
const STORAGE_SERVICES: usize = 5;
const INIT_STORAGE_HANDLES: usize = STORAGE_DRIVERS * 3 + STORAGE_SERVICES * 4;
/// A shell `run` of a file holds the file's Channel and the private memory
/// init reads it into, beside the loader's own handles.
const IMAGE_LAUNCH_HANDLES: usize = 2;
pub(super) const INIT_BASELINE_HANDLES: usize = sum(&INIT_RESIDENT_HANDLES) + INIT_STORAGE_HANDLES;

/// The six interactive roles and the seven storage roles.
const RESIDENT_IMAGES: usize = 6 + STORAGE_DRIVERS + STORAGE_SERVICES;
const RESIDENT_IMAGE_OBJECTS: usize = 2 + 1; // PT_LOADs plus initial stack.
/// Wyrmroot's job loader refuses an image with more than two PT_LOADs.
const JOB_IMAGE_OBJECTS: usize = 2 + 1; // PT_LOADs plus initial stack.
/// Each disk driver's BAR object and DMA object; fat32d's and ext4d's
/// attached buffers; each blockmgr's discovery buffer, open together with
/// the rest during boot; init's private copy of a file being launched.
const STORAGE_MEMORY: usize = STORAGE_DRIVERS * 2 + 2 + 2 + 1;
pub(super) const BASELINE_MEMORY: usize =
    RESIDENT_IMAGES * RESIDENT_IMAGE_OBJECTS + 1 + STORAGE_MEMORY; // + bootfs.

/// A replacement generation is constructed before the generation it replaces
/// is reaped, so exactly one role is doubled at the peak. Init's recovery is
/// serialized per role, so this is one, not five.
const REPLACEMENT_GENERATIONS: usize = 1;
/// Concurrent shell jobs, foreground and background together, orphans
/// included. Wyrmroot's init refuses a launch beyond this many (its
/// `MAX_SHELL_JOBS`), so the bound is enforced, not assumed (F4 DW1-F4-M1).
/// `spawn` made more than one job reachable; the earlier value of one was
/// stale.
const LIVE_SHELL_JOBS: usize = 4;
/// The wait items one job may register itself, enough for a small
/// wait-many. Wyrmroot limits each job's TaskGroup to this with
/// `task_group_limit`, and to no objects of its own.
const JOB_OWN_WAITS: usize = 4;
/// The mapping leases one job can hold. Its TaskGroup limits leave it one
/// Process, which has one root region of `REGION_SLOTS` mapping slots, and
/// it may map an object it holds into every slot. The lease pool is sized for
/// that, not for its image alone, so jobs cannot drain it.
pub(super) const JOB_REGION_MAPPINGS: usize = 10;
/// Init holds each live job's Process, TaskGroup and launch Channel.
const JOB_HELD_HANDLES: usize = 3;

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
/// attempt TaskGroup. Stream INIT staging retains at most four transferred
/// endpoints: three streams and, for a file job, its namespace (Wyrmroot WRLP
/// 1.13). Scratch memory closes before ThreadCreate. ChannelReduce briefly
/// needs the broad and reduced parent handles together with the child endpoint.
const STREAM_JOB_LOADER_HANDLES: usize = 1 + 4 + 1 + 2 + 1;
/// A devmgr replacement duplicates the resource-domain handle with sender-side
/// rights, holds the reduced handle it will MOVE, and retains the outgoing
/// generation's Process until it is reaped.
const REPLACEMENT_STAGING_HANDLES: usize = 3;
pub(super) const HANDLE_PEAK: usize = INIT_BASELINE_HANDLES
    + STREAM_JOB_LOADER_HANDLES
    + IMAGE_LAUNCH_HANDLES
    + REPLACEMENT_STAGING_HANDLES
    + LIVE_SHELL_JOBS * JOB_HELD_HANDLES;
pub(super) const MEMORY_PEAK: usize = BASELINE_MEMORY
    + REPLACEMENT_GENERATIONS * RESIDENT_IMAGE_OBJECTS
    + LIVE_SHELL_JOBS * JOB_IMAGE_OBJECTS
    + 1; // Loader scratch view, open until the child mapping is installed.
pub(super) const MAPPING_PEAK: usize =
    MEMORY_PEAK + LIVE_SHELL_JOBS * (JOB_REGION_MAPPINGS - JOB_IMAGE_OBJECTS);

/// Selector 33's baseline for this identical resident set: primordial->init,
/// init's five role startups, the service pairs to registryd, devmgr's
/// publication pair, the device control pair, consoled's launch pair and the
/// shell's job-control pair.
/// The storage roles' pairs: per disk driver its startup, devmgr control and
/// registry publication pairs; per service its startup and control pairs;
/// the publications (two blockmgrs, vfsd) and registry clients (two
/// blockmgrs, fat32d, ext4d); both filesystem roots to vfsd; each
/// filesystem's volume connection and blockmgr's driver connection behind
/// it; and a shell's vfsd connection with two open nodes.
const STORAGE_CHANNEL_PAIRS: usize =
    STORAGE_DRIVERS * 3 + STORAGE_SERVICES * 2 + 3 + 4 + 2 + 2 * 2 + 3;
pub(super) const BASELINE_CHANNEL_PAIRS: usize = 17 + STORAGE_CHANNEL_PAIRS;
/// A replacement generation brings its startup, control and publication pairs
/// before the outgoing generation's peers have closed.
const REPLACEMENT_CHANNEL_PAIRS: usize = 3;
/// Three stream pairs, one startup pair and, for a job launched from a file,
/// its namespace connection to vfsd (Wyrmroot WRLP 1.13), per live job.
const JOB_CHANNEL_PAIRS: usize = 3 + 1 + 1;
pub(super) const CHANNEL_PAIR_PEAK: usize =
    BASELINE_CHANNEL_PAIRS + REPLACEMENT_CHANNEL_PAIRS + LIVE_SHELL_JOBS * JOB_CHANNEL_PAIRS;
/// Conservative: both endpoints of every pair above are charged, rather than
/// assuming any particular peer has already observed close.
pub(super) const CHANNEL_ENDPOINT_PEAK: usize = 2 * CHANNEL_PAIR_PEAK;

/// devmgr owns the boot resource domain; the drivers hold the UART
/// DeviceResource with its one Interrupt and the two disks' PCI functions.
const DEVICE_RESOURCES: usize = 1 + STORAGE_DRIVERS;
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

// The six-role interactive graph's waits: 12 + 3 + 4 + 6 + 7 + 7 = 39, the
// controller's resident supervision set, the registry, device, console, shell
// and job sets. Taken from the retired selector-33 wait ledger (deepwyrm
// history before selector retirement), where an independent enumeration first
// reached 32 by missing rows.
pub(super) const INTERACTIVE_GRAPH_WAITS: usize = 12 + 3 + 4 + 6 + 7 + 7;
/// What this product adds to that graph: an exit wait apiece for the live job
/// and the replacement generation, each owning a Channel and a Process
/// registration.
const ADDED_EXIT_WAITS: usize = (LIVE_SHELL_JOBS + REPLACEMENT_GENERATIONS) * 2;
/// The storage roles' wait sets, each at its usual size: a disk driver's
/// control, publication and four connections; a blockmgr's control,
/// publication and three client links of two Channels each; fat32d's and
/// ext4d's control, root and four open nodes; vfsd's control, publication,
/// two mounts, two clients and two nodes; and init's exit wait per role.
const STORAGE_WAITS: usize = STORAGE_DRIVERS * 6
    + 2 * (2 + 3 * 2)
    + 2 * (2 + 4)
    + (2 + 2 + 2 + 2)
    + STORAGE_DRIVERS
    + STORAGE_SERVICES;
/// vfsd waits on every client connection it serves, and each live file job
/// holds one as its namespace.
const JOB_NAMESPACE_WAITS: usize = 1;
pub(super) const WAIT_PEAK: usize = INTERACTIVE_GRAPH_WAITS
    + ADDED_EXIT_WAITS
    + LIVE_SHELL_JOBS * (JOB_OWN_WAITS + JOB_NAMESPACE_WAITS)
    + STORAGE_WAITS;

// Wyrmroot owns the archive parser, whose selected record limit is 4096.
// The product archive (`wyrmroot_bootfs::product`) holds thirteen
// executables -- six roles, `bin/hello`, `bin/cpu-hog` and the five storage
// executables (`virtio-blkd`, `blockmgr`, `fat32d`, `ext4d`, `vfsd`; the
// disks and volumes share theirs) -- and four bootstrap entries: launch
// policy, `rrc-a-v1`, the device manifest and the product marker. No extra
// kernel object is made per entry.
pub(super) const BOOTFS_ENTRY_PEAK: usize = 13 + 4;
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

/// Each pool sits clear of its peak, so the next storage or package role is
/// an edit to this ledger rather than a product that silently stops booting.
pub(super) const SELECTED: Capacity = Capacity {
    handles: 96,
    memory: 96,
    mappings: 128,
    identities: 32,
    registry: 384,
    channel_pairs: 96,
    waits: 160,
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
// and this ledger move together: W7 raised both to thirty-two, deliberately,
// in `task_layout.toml`.
const _: () = assert!(SELECTED.identities <= crate::memory::kernel_stack::E3_THREAD_STACK_COUNT);
// Selector 33's 64-handle tables were avoided while the product's demand
// stayed under 48. With the storage spine, init alone holds 47 handles at
// rest and its peak is past 64, so the tables are wider than E8's; the bound
// keeps a stray edit from widening them further unexamined.
const _: () = assert!(SELECTED.handles <= 96);
// The production product carries no evidence collector. If `test-support` is
// ever admitted into a production build this ledger must be revisited rather
// than silently inheriting a selector's record capacity.
const _: () = assert!(SELECTED.evidence == 0);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn the_selected_capacities_are_the_numbers_the_f_receipt_binds() {
        // Wyrmroot's `tools/xtask/src/wyr1f.rs` writes these into every WYR1-F
        // freeze receipt as `kernel_identity_capacity`,
        // `kernel_handle_capacity`, `kernel_registry_capacity` and
        // `kernel_thread_stack_count`. It cannot read them from here, so this
        // is the reconciliation: a capacity change fails in this repository
        // before it can reach a product whose receipt still claims the old
        // figure.
        assert_eq!(SELECTED.identities, 32);
        assert_eq!(SELECTED.handles, 96);
        assert_eq!(SELECTED.registry, 384);
        // Production links the ordinary arena. Only the E8 and F-closure
        // fairness builds link sixty-four stacks (`kernel_stack.rs`), and this
        // module is compiled into their host tests too.
        assert_eq!(crate::memory::kernel_stack::E3_THREAD_STACK_COUNT, 32);
    }

    #[test]
    fn production_peaks_are_the_documented_arithmetic() {
        assert_eq!(INIT_STORAGE_HANDLES, 26);
        assert_eq!(INIT_BASELINE_HANDLES, 47);
        assert_eq!(STREAM_JOB_LOADER_HANDLES, 9);
        assert_eq!(HANDLE_PEAK, 73);
        assert_eq!(RESIDENT_IMAGES, 13);
        assert_eq!(STORAGE_MEMORY, 9);
        assert_eq!(BASELINE_MEMORY, 49);
        assert_eq!(MEMORY_PEAK, 65);
        assert_eq!(MAPPING_PEAK, 93);
        assert_eq!(LIVE_PROCESSES, 18);
        assert_eq!(LIVE_TASK_GROUPS, 21);
        assert_eq!(LIVE_IDENTITY_PEAK, 21);
        assert_eq!(STORAGE_CHANNEL_PAIRS, 32);
        assert_eq!(CHANNEL_PAIR_PEAK, 72);
        assert_eq!(CHANNEL_ENDPOINT_PEAK, 144);
        assert_eq!(REGISTRY_PEAK, 290);
        assert_eq!(INTERACTIVE_GRAPH_WAITS, 39);
        assert_eq!(STORAGE_WAITS, 55);
        assert_eq!(WAIT_PEAK, 124);
        assert_eq!(BOOTFS_ENTRY_PEAK, 17);
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
        // Twenty-three lifetime identities, twenty-one simultaneous. The census is
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
