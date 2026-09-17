//! WYR1-F fairness-leg demand: a test-support kernel resource geometry sized
//! for the E8 scheduler/fairness leg, as distinct from
//! `production_resource_geometry`'s single-live-job production demand.
//!
//! This is a source/host capacity model, not live acceptance. Cite F3A.6p.
//!
//! `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` (amendment F3A.6o) records the defect
//! this ledger answers: `production_resource_geometry.rs` derives every
//! capacity from `LIVE_SHELL_JOBS: usize = 1`, so a second *concurrent* shell
//! job was never a reachable state of that model, and a live run refused the
//! second concurrent job with the launch protocol's `capacity` code. F3A.6o
//! is explicit that raising the *production* geometry is deferred, not
//! refused, pending a product that boots and a measured job count. This
//! ledger does neither: it is a `test-support`-gated fixture that can host
//! the fairness leg without moving `production_resource_geometry::SELECTED`
//! or its frozen four figures at all.
//!
//! Topology is `production_resource_geometry`'s frozen WYR1-F spine (the same
//! six resident roles, one overlapping replacement generation, and the same
//! three structural TaskGroups), generalized from one live job to the
//! fairness leg's concurrent-hog graph. Per
//! `WYR1E_DW1F_WYR1F_IMPLEMENTATION_PLAN.md` "E8 scheduler/fairness leg": on
//! the four-vCPU profile, launch at least six concurrent CPU hogs through
//! `spawn`, and *while they run*, repeatedly issue `echo`/`status`/`tasks`
//! and one `run bin/hello`. So the peak graph is not N streamed jobs -- per
//! `WYR1_E_WYRMSH_CONTRACT`/the WYR1-E implementation plan section 3.13,
//! `spawn` "deliberately receives no startup streams in WYR1-E", so a hog is
//! zero-stream exactly like selector 33/E8's own hogs. The one streamed job
//! live at the peak instant is the interleaved `run bin/hello`
//! responsiveness probe. This is the point on which this ledger deliberately
//! disagrees with a literal "every job costs three stream pairs" reading:
//! that reading is wrong for the six (or two) hogs and right for the one
//! probe, and the two are sized differently below for exactly that reason.

pub(super) const LIFETIME_IDENTITIES: [&str; 19] = [
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
    "driver-attempt-2",
    "hog-1",
    "hog-2",
    "hog-3",
    "hog-4",
    "hog-5",
    "hog-6",
    "hello-probe",
];

// init's own four authorities; registryd Process/TaskGroup/bootstrap/control;
// devmgr Process/bootstrap/publication; UART Process/bootstrap/control;
// consoled Process/bootstrap/registry/launch; shell Process/TaskGroup/job
// endpoint. Identical to `production_resource_geometry`'s baseline: the
// resident set is the same six roles.
const INIT_RESIDENT_HANDLES: [usize; 6] = [4, 4, 3, 3, 4, 3];
pub(super) const INIT_BASELINE_HANDLES: usize = sum(&INIT_RESIDENT_HANDLES);

const RESIDENT_IMAGES: usize = 6;
const RESIDENT_IMAGE_OBJECTS: usize = 2 + 1; // PT_LOADs plus initial stack.
pub(super) const BASELINE_MEMORY: usize = RESIDENT_IMAGES * RESIDENT_IMAGE_OBJECTS + 1; // + bootfs.

/// Recovery overlaps the fairness leg the same way it overlaps production:
/// exactly one role is doubled at the peak (`production_resource_geometry`'s
/// `REPLACEMENT_GENERATIONS`).
const REPLACEMENT_GENERATIONS: usize = 1;
/// The bootstrap root, the long-lived resource domain, and the driver-attempt
/// group -- unaffected by hog count, identical to production's
/// `STRUCTURAL_TASK_GROUPS`.
const STRUCTURAL_TASK_GROUPS: usize = 3;

/// "E8 scheduler/fairness leg": the four-vCPU profile's obligation is "more
/// hogs than CPUs", stated there as "at least six". This is `N = 6`.
pub(super) const HOG_JOBS: usize = 6;
/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` F3A.6o: `HOG_JOBS` is
/// `{default: 2, smp: 6}`, i.e. the one-vCPU profile needs only two
/// concurrent hogs -- and F3A.6o records that the live product refused the
/// *second* one. Kept host-side only (see the tests below) because this
/// ledger's own `SELECTED` is sized for the six-hog profile it is meant to
/// carry; the two-hog figures exist so a later reader can see what the
/// smaller profile would have needed without a second selected geometry.
#[cfg(test)]
const UP_PROFILE_HOG_JOBS: usize = 2;

/// A hog is spawned zero-stream (WYR1-E section 3.13); the interleaved
/// `run bin/hello` is the one streamed job live at the peak instant.
const RESPONSIVENESS_PROBES: usize = 1;

pub(super) const fn live_processes(hog_jobs: usize) -> usize {
    RESIDENT_IMAGES + REPLACEMENT_GENERATIONS + hog_jobs + RESPONSIVENESS_PROBES
}
pub(super) const fn live_task_groups(hog_jobs: usize) -> usize {
    live_processes(hog_jobs) + STRUCTURAL_TASK_GROUPS
}
/// Every pool indexed by identity is bounded by simultaneous occupancy
/// (`production_resource_geometry`'s own rule), so the peak is the larger of
/// the two live counts; `live_task_groups` always dominates here because
/// `STRUCTURAL_TASK_GROUPS > 0`.
pub(super) const fn live_identity_peak(hog_jobs: usize) -> usize {
    let processes = live_processes(hog_jobs);
    let groups = live_task_groups(hog_jobs);
    if processes > groups {
        processes
    } else {
        groups
    }
}

pub(super) const LIVE_PROCESSES: usize = live_processes(HOG_JOBS);
pub(super) const LIVE_TASK_GROUPS: usize = live_task_groups(HOG_JOBS);
/// Six concurrent hogs plus the one streamed probe cross the ordinary
/// sixteen-stack arena: `live_identity_peak(6) == 17`. The two-hog profile
/// does not (`live_identity_peak(2) == 13`, pinned below), so the arena was
/// never that profile's actual wall -- see the handle arithmetic below for
/// what was.
pub(super) const LIVE_IDENTITY_PEAK: usize = live_identity_peak(HOG_JOBS);

/// A hog's single PT_LOAD (zero-stream, selector 33/E8's own image shape)
/// plus its stack.
const HOG_IMAGE_OBJECTS: usize = 1 + 1;
/// `bin/hello`'s two PT_LOADs plus its stack, identical to
/// `production_resource_geometry::JOB_IMAGE_OBJECTS`.
const PROBE_IMAGE_OBJECTS: usize = 2 + 1;

pub(super) const fn memory_peak(hog_jobs: usize) -> usize {
    BASELINE_MEMORY
        + REPLACEMENT_GENERATIONS * RESIDENT_IMAGE_OBJECTS
        + hog_jobs * HOG_IMAGE_OBJECTS
        + RESPONSIVENESS_PROBES * PROBE_IMAGE_OBJECTS
        + 1 // Loader scratch view, open until the child mapping is installed.
}
pub(super) const MEMORY_PEAK: usize = memory_peak(HOG_JOBS);
pub(super) const MAPPING_PEAK: usize = MEMORY_PEAK;

/// Loader stages are additive to the caller's existing handles and one new
/// attempt TaskGroup; Stream INIT staging retains at most three transferred
/// endpoints regardless of whether the job ends up streamed, because the
/// staging cost is paid before the job's own stream count is known.
/// Identical to selector 33/E8's own `STREAM_JOB_LOADER_HANDLES`.
const STREAM_JOB_LOADER_HANDLES: usize = 1 + 3 + 1 + 2 + 1;
/// A devmgr replacement duplicates the resource-domain handle with sender-side
/// rights, holds the reduced handle it will MOVE, and retains the outgoing
/// generation's Process until it is reaped. Identical to
/// `production_resource_geometry::REPLACEMENT_STAGING_HANDLES`.
const REPLACEMENT_STAGING_HANDLES: usize = 3;
/// Process and TaskGroup only; no stream handles, per selector 33/E8's own
/// `HOG_RETAINED_HANDLES`.
const HOG_RETAINED_HANDLES: usize = 2;
/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` F3A.6o: "every live job's three
/// stream pairs" is the shell's own accounting of a *streamed* live job's
/// retained handle cost -- one handle per stream endpoint the shell keeps to
/// pump stdin/stdout/stderr, distinct from the exit-wait Channel and Process
/// registration `production_resource_geometry` counts against `WAITERS`.
const PROBE_RETAINED_HANDLES: usize = 3;

/// Exactly one job is in its transient loader stage at the peak instant; the
/// rest are already launched and retained. The maximum is reached by putting
/// a *hog* (the cheaper retained job, cost 2) in the loader rather than the
/// probe (cost 3), keeping the more expensive already-launched job counted:
/// removing the hog from the steady sum loses less than removing the probe
/// would. `hog_jobs >= 1` is required (true for both profiles below).
pub(super) const fn handle_peak(hog_jobs: usize) -> usize {
    INIT_BASELINE_HANDLES
        + REPLACEMENT_STAGING_HANDLES
        + STREAM_JOB_LOADER_HANDLES
        + (hog_jobs - 1) * HOG_RETAINED_HANDLES
        + RESPONSIVENESS_PROBES * PROBE_RETAINED_HANDLES
}
pub(super) const HANDLE_PEAK: usize = handle_peak(HOG_JOBS);

/// Selector 33/E8's baseline for this identical resident set: primordial ->
/// init, init's five role startups, the service pairs to registryd, devmgr's
/// publication pair, the device control pair, consoled's launch pair and the
/// shell's job-control pair.
const BASELINE_CHANNEL_PAIRS: usize = 17;
const REPLACEMENT_CHANNEL_PAIRS: usize = 3;
/// A hog is zero-stream but still retains its one-sided job-control/startup
/// pair, per selector 33/E8's own model ("each of the six hogs may retain its
/// one-sided startup pair").
const HOG_CHANNEL_PAIRS: usize = 1;
/// Three stream pairs and one startup pair, per
/// `production_resource_geometry::JOB_CHANNEL_PAIRS`.
const PROBE_CHANNEL_PAIRS: usize = 3 + 1;

pub(super) const fn channel_pair_peak(hog_jobs: usize) -> usize {
    BASELINE_CHANNEL_PAIRS
        + REPLACEMENT_CHANNEL_PAIRS
        + hog_jobs * HOG_CHANNEL_PAIRS
        + RESPONSIVENESS_PROBES * PROBE_CHANNEL_PAIRS
}
pub(super) const CHANNEL_PAIR_PEAK: usize = channel_pair_peak(HOG_JOBS);
/// Conservative like `production_resource_geometry`: both endpoints of every
/// pair are charged, rather than assuming any particular peer has already
/// observed close.
pub(super) const fn channel_endpoint_peak(hog_jobs: usize) -> usize {
    2 * channel_pair_peak(hog_jobs)
}
pub(super) const CHANNEL_ENDPOINT_PEAK: usize = channel_endpoint_peak(HOG_JOBS);

/// devmgr owns the boot resource domain; the driver holds the one UART
/// DeviceResource and its one Interrupt. Unaffected by hog count.
const DEVICE_RESOURCES: usize = 1;
const INTERRUPTS: usize = 1;
/// The UART pacing Timer and init's resident control tick can overlap.
pub(super) const TIMER_PEAK: usize = 2;
pub(super) const EVENT_PEAK: usize = 0;
pub(super) const REGION_MAPPING_PEAK: usize = 2 + 1 + 1 + 1; // PT_LOADs, stack, bootfs, scratch.

pub(super) const fn registry_peak(hog_jobs: usize) -> usize {
    live_processes(hog_jobs) * 3 // Process, Thread, root
        + live_task_groups(hog_jobs)
        + memory_peak(hog_jobs)
        + channel_endpoint_peak(hog_jobs)
        + DEVICE_RESOURCES
        + INTERRUPTS
        + TIMER_PEAK
}
pub(super) const REGISTRY_PEAK: usize = registry_peak(HOG_JOBS);

/// Reused, not re-derived, exactly as `production_resource_geometry` reuses
/// `wyr1e_wait_geometry`'s non-E8 arm for this same six-role interactive
/// graph: the controller's resident supervision set, the registry, device,
/// console, shell and job sets (12 + 3 + 4 + 6 + 7 + 7 = 39).
const INTERACTIVE_GRAPH_WAITS: usize = 12 + 3 + 4 + 6 + 7 + 7;
/// What this leg adds to that graph: an exit wait apiece for every live hog,
/// the probe, and the replacement generation, each owning a Channel and a
/// Process registration (`production_resource_geometry::ADDED_EXIT_WAITS`).
pub(super) const fn wait_peak(hog_jobs: usize) -> usize {
    INTERACTIVE_GRAPH_WAITS + (hog_jobs + RESPONSIVENESS_PROBES + REPLACEMENT_GENERATIONS) * 2
}
pub(super) const WAIT_PEAK: usize = wait_peak(HOG_JOBS);

// Wyrmroot owns the archive parser, whose selected record limit is 4096. Same
// six role executables and five bootstrap configuration entries as
// `production_resource_geometry::BOOTFS_ENTRY_PEAK`, plus `bin/hello` and one
// dedicated CPU-hog binary the fairness leg spawns repeatedly.
pub(super) const BOOTFS_ENTRY_PEAK: usize = 6 + 5 + 1 + 1;
pub(super) const BOOTFS_ENTRY_CAPACITY: usize = 4096;

/// This fixture produces no evidence records of its own; it exists to host a
/// live scenario, not to collect one.
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
    pub identities: usize,
    pub registry: usize,
    pub channel_pairs: usize,
    pub waits: usize,
    pub evidence: usize,
}

// WYR1F_FAIRNESS_SELECTED_CAPACITIES per_process_handle_capacity=64 memory_object_capacity=64 mapping_lease_capacity=64 registry_object_capacity=192
pub(super) const SELECTED: Capacity = Capacity {
    handles: 64,
    memory: 64,
    mappings: 64,
    identities: 64,
    registry: 192,
    channel_pairs: 64,
    waits: 64,
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
        && capacity.evidence == EVIDENCE_PEAK
}

const _: () = assert!(fits(SELECTED));
// `identities` becomes `THREADS`, and every Thread needs one of the linked
// per-thread kernel stacks; see `production_resource_geometry`'s identical
// comment. Six concurrent hogs plus the interleaved probe need seventeen
// simultaneous identities, which the ordinary sixteen-stack arena cannot
// hold, so this ledger is gated on its own cfg -- `deepwyrm_wyr1f_fairness_evidence`
// -- rather than reusing `deepwyrm_wyr1e8_evidence`. Sharing E8's cfg would
// silently tie the F fairness leg's arena to E8's evidence-collection
// machinery (its own 64-identity task-family headroom, its evidence
// collector, its selector-33 scenario), none of which this leg is. The
// numeric arena size (64) is reused only because it is already an accepted,
// tested value comfortably above this ledger's 17-identity demand -- not
// because the two selectors share anything else.
#[cfg(deepwyrm_wyr1f_fairness_evidence)]
const _: () = assert!(SELECTED.identities <= crate::memory::kernel_stack::E3_THREAD_STACK_COUNT);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// The target-side assertion above is selector-gated, because the linked
    /// arena is. This is the same relation read from source, so the host
    /// gate fails too when either side moves.
    #[test]
    fn wyr1f_fairness_identities_fit_the_arena_this_selector_links() {
        let declared = std::format!(
            "pub(crate) const E3_THREAD_STACK_COUNT: usize = {};",
            SELECTED.identities
        );
        let source = include_str!("../../../../memory/kernel_stack.rs");
        let selected = source
            .lines()
            .skip_while(|line| *line != "#[cfg(all(deepwyrm_wyr1f_fairness_evidence, not(deepwyrm_wyr1e8_evidence)))]")
            .nth(1)
            .expect("kernel_stack.rs declares a wyr1f-fairness-gated thread-stack count");
        assert_eq!(
            selected.trim(),
            declared,
            "the wyr1f fairness leg links a thread-stack arena that no longer matches this ledger's identities"
        );
    }

    #[test]
    fn wyr1f_fairness_selected_marker_matches_executable_capacities() {
        let marker = std::format!(
            "// WYR1F_FAIRNESS_SELECTED_CAPACITIES per_process_handle_capacity={} memory_object_capacity={} mapping_lease_capacity={} registry_object_capacity={}",
            SELECTED.handles,
            SELECTED.memory,
            SELECTED.mappings,
            SELECTED.registry,
        );
        assert_eq!(
            include_str!("wyr1f_fairness_resource_geometry.rs")
                .lines()
                .filter(|line| *line == marker)
                .count(),
            1
        );
    }

    #[test]
    fn wyr1f_fairness_six_hog_peaks_are_the_documented_arithmetic() {
        assert_eq!(INIT_BASELINE_HANDLES, 21);
        assert_eq!(BASELINE_MEMORY, 19);
        assert_eq!(LIVE_PROCESSES, 14);
        assert_eq!(LIVE_TASK_GROUPS, 17);
        assert_eq!(LIVE_IDENTITY_PEAK, 17);
        assert_eq!(HANDLE_PEAK, 45);
        assert_eq!(MEMORY_PEAK, 38);
        assert_eq!(MAPPING_PEAK, 38);
        assert_eq!(CHANNEL_PAIR_PEAK, 30);
        assert_eq!(CHANNEL_ENDPOINT_PEAK, 60);
        assert_eq!(REGISTRY_PEAK, 161);
        assert_eq!(WAIT_PEAK, 55);
        assert_eq!(BOOTFS_ENTRY_PEAK, 13);
        const { assert!(BOOTFS_ENTRY_PEAK < BOOTFS_ENTRY_CAPACITY) };
    }

    /// What the one-vCPU profile's two hogs would have needed, so a later
    /// reader can see both without a second selected geometry. The arena
    /// (`LIVE_IDENTITY_PEAK` against sixteen) was never this profile's wall;
    /// its handle peak already exceeds the live `wyr1e-interactive`
    /// thirty-two-handle geometry the F products actually declare
    /// (`DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` F3A.6o), which is consistent
    /// with the refusal happening on the *second* concurrent job.
    #[test]
    fn wyr1f_fairness_two_hog_up_profile_peaks_are_the_documented_arithmetic() {
        assert_eq!(live_processes(UP_PROFILE_HOG_JOBS), 10);
        assert_eq!(live_task_groups(UP_PROFILE_HOG_JOBS), 13);
        assert_eq!(live_identity_peak(UP_PROFILE_HOG_JOBS), 13);
        assert!(live_identity_peak(UP_PROFILE_HOG_JOBS) <= 16);
        assert_eq!(handle_peak(UP_PROFILE_HOG_JOBS), 37);
        assert!(handle_peak(UP_PROFILE_HOG_JOBS) > 32);
        assert_eq!(memory_peak(UP_PROFILE_HOG_JOBS), 30);
        assert_eq!(channel_pair_peak(UP_PROFILE_HOG_JOBS), 26);
        assert_eq!(channel_endpoint_peak(UP_PROFILE_HOG_JOBS), 52);
        assert_eq!(registry_peak(UP_PROFILE_HOG_JOBS), 129);
        assert_eq!(wait_peak(UP_PROFILE_HOG_JOBS), 47);
    }

    #[test]
    fn wyr1f_fairness_six_hog_bounds_pass_and_smaller_pools_fail() {
        assert!(fits(SELECTED));
        for smaller in [
            Capacity {
                handles: HANDLE_PEAK - 1,
                ..SELECTED
            },
            Capacity {
                memory: MEMORY_PEAK - 1,
                ..SELECTED
            },
            Capacity {
                mappings: MAPPING_PEAK - 1,
                ..SELECTED
            },
            Capacity {
                identities: LIVE_IDENTITY_PEAK - 1,
                ..SELECTED
            },
            Capacity {
                registry: REGISTRY_PEAK - 1,
                ..SELECTED
            },
            Capacity {
                channel_pairs: CHANNEL_PAIR_PEAK - 1,
                ..SELECTED
            },
            Capacity {
                waits: WAIT_PEAK - 1,
                ..SELECTED
            },
        ] {
            assert!(!fits(smaller));
        }
        // The ordinary sixteen-identity arena cannot host the six-hog leg.
        assert!(!fits(Capacity {
            identities: 16,
            ..SELECTED
        }));
    }

    #[test]
    fn wyr1f_fairness_lifetime_census_is_not_used_as_a_capacity() {
        for (index, identity) in LIFETIME_IDENTITIES.iter().enumerate() {
            assert!(!LIFETIME_IDENTITIES[..index].contains(identity));
        }
        assert_eq!(LIFETIME_IDENTITIES.len(), 19);
        assert!(LIFETIME_IDENTITIES.len() > LIVE_IDENTITY_PEAK);
    }
}
