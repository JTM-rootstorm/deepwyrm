//! Selector-34 R1 saturation-probe demand, separate from production policy.
//!
//! This is a source/host capacity model, not live acceptance. Before this
//! ledger existed selector 34 silently inherited the bootstrap-era default
//! geometry — 3 identities, 10 handles, 10 MemoryObjects, 1 TaskGroup — which
//! cannot run a probe that launches six hogs plus a progress child after each
//! one. `DW1_WYR1_RUNTIME_RESET_IMPLEMENTATION_PLAN.md` section 10 forbids
//! exactly that: a selector must not silently inherit an unrelated older
//! capacity merely because no source constant was overridden.
//!
//! Topology comes from Wyrmroot's `r1-saturation` scenario and the card R1C
//! product artifact list. Resident images are `system-init`, `registryd`,
//! `devmgr` and the probe; there is deliberately no UART driver, no consoled,
//! no shell and no output-pressure actor, so every actor here is zero-stream.
//! Resident images and the `hello` progress child have two PT_LOAD segments;
//! zero-stream hogs have one. The loader owns one object per segment plus one
//! stack object and unmaps its scratch view before mapping the child.
//!
//! Sized at the scenario's own `MAX_HOGS` ceiling of eight rather than the
//! six-hog SMP plan. The scenario already fixes its buffers at eight, and
//! sizing at exactly six would make a plan change to seven or eight hogs
//! silently require a kernel capacity change — the drift this ledger exists to
//! prevent. Both the selected plan and the ceiling are asserted below.
//!
//! The product-shape inputs — init's resident handle sets, the channel
//! topology, and the supervision wait structure — are design decisions recorded
//! here because card R1's RRC manifest and launch policy do not exist yet. The
//! product must satisfy this ledger or reconcile it; the asserts and fixtures
//! below are what make a deviation fail loudly instead of silently.

/// Hogs the scenario can launch. Mirrors `wyrmroot`'s `r1_saturation::MAX_HOGS`
/// and is the ceiling this geometry is sized for, not the selected plan.
pub(super) const MAX_HOGS: usize = 8;
/// The canonical four-vCPU SMP plan's hog count, and the one-vCPU control's.
pub(super) const SMP_PLAN_HOGS: usize = 6;
pub(super) const CONTROL_PLAN_HOGS: usize = 3;
/// Observable steps per hog: launch, accept, progress launch, progress result,
/// then terminate and result. Mirrors `ProbePlan::step_budget`.
pub(super) const STEPS_PER_HOG: usize = 6;

// Enumerate every lifetime identity, including finalized generations. Rejected
// launches never publish a Process, so a `HogRejected` or `ProgressRejected`
// run consumes fewer.
//
// **This census sizes no capacity.** It is a record of the task families the
// run creates over its whole lifetime, used only to check that the scenario was
// enumerated rather than estimated. Every pool below is sized from a
// *simultaneous* peak instead, because the kernel's identity tables are
// occupancy bounds and a finalized generation releases its slot. Treating this
// number as a capacity is what the split recorded at `LIVE_IDENTITY_PEAK`
// exists to prevent.
pub(super) const LIFETIME_IDENTITIES: [&str; 21] = [
    "primordial",
    "system-init",
    "registryd",
    "devmgr",
    "r1-saturation-probe",
    "hog-1",
    "hog-2",
    "hog-3",
    "hog-4",
    "hog-5",
    "hog-6",
    "hog-7",
    "hog-8",
    "progress-1",
    "progress-2",
    "progress-3",
    "progress-4",
    "progress-5",
    "progress-6",
    "progress-7",
    "progress-8",
];

const RESIDENT_IMAGES: usize = 4; // system-init, registryd, devmgr, probe.
const RESIDENT_IMAGE_OBJECTS: usize = 2 + 1; // PT_LOADs plus initial stack.
const HOG_IMAGE_OBJECTS: usize = 1 + 1; // One PT_LOAD; zero-stream.
const PROGRESS_IMAGE_OBJECTS: usize = 2 + 1; // `hello` has two PT_LOADs.

// init's own four authorities; registryd Process/TaskGroup/bootstrap/control;
// devmgr Process/bootstrap/publication; probe Process/TaskGroup/job endpoint.
// Smaller than E8's equivalent precisely because no UART, consoled or shell
// generation exists in this product.
const INIT_RESIDENT_HANDLES: [usize; 4] = [4, 4, 3, 3];
pub(super) const INIT_BASELINE_HANDLES: usize = sum(&INIT_RESIDENT_HANDLES);
/// Process and TaskGroup. No stream handles: hogs are zero-stream by design.
const HOG_RETAINED_HANDLES: usize = 2;
/// One new attempt TaskGroup, the net ChannelCreate/reduce handle, the child
/// Process and root, its Thread, and the two parent handles ChannelReduce
/// briefly needs together with the child endpoint. Additive to the caller's
/// existing handles. This is the zero-stream path; E8 needed a larger delta
/// only because its actors staged three transferred stream endpoints.
const ZERO_STREAM_LOADER_HANDLES: usize = 1 + 1 + 2 + 1 + 2;

pub(super) const BASELINE_MEMORY: usize = RESIDENT_IMAGES * RESIDENT_IMAGE_OBJECTS + 1; // + bootfs.

// The scenario never terminates a hog until every hog has launched and its
// progress cycle has completed: `observe_progress_result` moves to
// `Phase::TerminateHog` only once `cursor + 1 >= hog_count`. So all hogs are
// simultaneously live at the peak, alongside exactly one progress child —
// `progress_job` is set per cycle and cleared on its terminal result.
pub(super) const LIVE_PROCESSES: usize = RESIDENT_IMAGES + MAX_HOGS + 1;
pub(super) const LIVE_TASK_GROUPS: usize = LIVE_PROCESSES + 1; // Plus root.

// Every pool indexed by identity — Process, Thread, address space, region,
// region object, TaskGroup and execution thread — is bounded by simultaneous
// occupancy, so the peak is the larger of the two live counts above. Primordial
// is absent from it deliberately: it has retired long before the first hog
// launches, so charging it here would reserve a slot nothing can occupy.
pub(super) const LIVE_IDENTITY_PEAK: usize = if LIVE_PROCESSES > LIVE_TASK_GROUPS {
    LIVE_PROCESSES
} else {
    LIVE_TASK_GROUPS
};

pub(super) const HANDLE_PEAK: usize =
    INIT_BASELINE_HANDLES + MAX_HOGS * HOG_RETAINED_HANDLES + ZERO_STREAM_LOADER_HANDLES;
pub(super) const MEMORY_PEAK: usize =
    BASELINE_MEMORY + MAX_HOGS * HOG_IMAGE_OBJECTS + PROGRESS_IMAGE_OBJECTS;
pub(super) const MAPPING_PEAK: usize = MEMORY_PEAK;

// primordial->init startup; init->registryd/devmgr/probe startup; the
// init<->registryd, devmgr<->registryd and probe<->registryd service pairs;
// devmgr's publication pair; and the probe's WRLJ job-control pair to init.
pub(super) const BASELINE_CHANNEL_PAIRS: usize = 1 + 3 + 3 + 1 + 1;
// A hog need not yet have observed parent peer-close, so each may retain its
// one-sided startup pair. The live progress child adds one startup pair.
pub(super) const CHANNEL_PAIR_PEAK: usize = BASELINE_CHANNEL_PAIRS + MAX_HOGS + 1;
// Conservative: both endpoints of every baseline pair, plus each hog's retained
// one-sided endpoint, plus the progress child's pair.
pub(super) const CHANNEL_ENDPOINT_PEAK: usize = 2 * BASELINE_CHANNEL_PAIRS + MAX_HOGS + 2;

// devmgr owns the boot resource domain; there is no driver, so no Interrupt and
// no UART pacing Timer. init's resident control tick is the only Timer.
const DEVICE_RESOURCES: usize = 1;
pub(super) const TIMER_PEAK: usize = 1;
pub(super) const EVENT_PEAK: usize = 0;
pub(super) const REGION_MAPPING_PEAK: usize = 2 + 1 + 1 + 1; // PT_LOADs, stack, bootfs, scratch.

pub(super) const REGISTRY_PEAK: usize = LIVE_PROCESSES * 3 // Process, Thread, root
    + LIVE_TASK_GROUPS
    + MEMORY_PEAK
    + CHANNEL_ENDPOINT_PEAK
    + DEVICE_RESOURCES
    + TIMER_PEAK;

// Each WAIT_ANY owns a Channel and a Process registration. init supervises its
// four resident children, holds one in-flight synchronous READY wait — the
// exact A27 shape this probe reproduces, which R6 later makes asynchronous —
// and holds an exit wait per live hog and the live progress child. The probe
// waits on its own job replies.
const INIT_RESIDENT_SUPERVISION_WAITS: usize = RESIDENT_IMAGES * 2;
const INIT_SYNCHRONOUS_READY_WAIT: usize = 2;
const INIT_CHILD_EXIT_WAITS: usize = (MAX_HOGS + 1) * 2;
const PROBE_REPLY_WAITS: usize = 2;
pub(super) const WAIT_PEAK: usize = INIT_RESIDENT_SUPERVISION_WAITS
    + INIT_SYNCHRONOUS_READY_WAIT
    + INIT_CHILD_EXIT_WAITS
    + PROBE_REPLY_WAITS;

// Wyrmroot owns the archive parser, whose selected record limit is 4096. R1 is
// the ten-entry C1 base plus policy and the six actor files.
// Reconciled against the built archive, 2026-09-12 (`wyrmroot` `build_r1`):
// WYR1-C1's ten entries, the launch policy and the WRR1 probe configuration,
// and three payloads — the probe, the reused `bin/cpu-hog` and `bin/hello`. The
// earlier estimate of 10 + 1 + 6 predated the product and over-counted the
// payloads by two; it was safe because this is checked against a 4096-entry
// capacity, but an estimate that no longer matches the product is worth less
// than the product's own composition.
pub(super) const BOOTFS_ENTRY_PEAK: usize = 10 + 2 + 3;
pub(super) const BOOTFS_ENTRY_CAPACITY: usize = 4096;

// One R1SP record per observed step, plus at most one failure record and
// exactly one terminal record.
pub(super) const EVIDENCE_SMP_PEAK: usize = SMP_PLAN_HOGS * STEPS_PER_HOG + 1 + 1;
pub(super) const EVIDENCE_CONTROL_PEAK: usize = CONTROL_PLAN_HOGS * STEPS_PER_HOG + 1 + 1;
pub(super) const EVIDENCE_CEILING_PEAK: usize = MAX_HOGS * STEPS_PER_HOG + 1 + 1;

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

// R1_SELECTED_CAPACITIES per_process_handle_capacity=48 memory_object_capacity=48 mapping_lease_capacity=48 registry_object_capacity=160
pub(super) const SELECTED: Capacity = Capacity {
    handles: 48,
    memory: 48,
    mappings: 48,
    identities: 16,
    registry: 160,
    channel_pairs: 24,
    waits: 48,
    evidence: 64,
};

pub(super) const fn fits(capacity: Capacity) -> bool {
    capacity.handles >= HANDLE_PEAK
        && capacity.memory >= MEMORY_PEAK
        && capacity.mappings >= MAPPING_PEAK
        && capacity.identities >= LIVE_IDENTITY_PEAK
        && capacity.registry >= REGISTRY_PEAK
        && capacity.channel_pairs >= CHANNEL_PAIR_PEAK
        && capacity.waits >= WAIT_PEAK
        && capacity.evidence >= EVIDENCE_CEILING_PEAK
}

const _: () = assert!(fits(SELECTED));
// The ceiling that the first selection of this ledger missed, with the failure
// mode spelled out because it is silent and does not look like a capacity bug.
//
// `identities` becomes `THREADS`, and every Thread needs one of the linked
// per-thread kernel stacks. Selecting more Threads than the arena has stacks
// does not fail a bounds check at run time: it makes thread creation
// unsatisfiable for constants the optimizer can see, so a release build folds
// `primordial::enter` to a panic, `--gc-sections` drops every subsystem the
// folded continuation no longer reaches, and the artifact boots no product at
// all. The first selection here was 32 against an arena of 16, and the
// resulting kernel carried 584 symbols with no scheduler, IPC or syscall
// surface, while a debug build of the same source carried 13,878 and the full
// runtime. Measured 2026-09-12; see `DW1_WYR1_RESET_R1C_VM_REQUEST.md` §8.
//
// Raising the arena instead is not the remedy. The alternative linked geometry
// is E8's 64 x 4 MiB, whose widened tables are why its termination path needed
// a 4 MiB per-thread stack, and plan §12 forbids growing a multi-megabyte stack
// in place of reducing frames.
const _: () = assert!(SELECTED.identities <= crate::memory::kernel_stack::E3_THREAD_STACK_COUNT);
// The ledger does not get its own opinion about how many records the collector
// can hold. A capacity change on either side must be reconciled here. Gated on
// the feature that admits `test_support` at all; the collector cannot exist
// without it, so there is nothing to reconcile when it is absent.
#[cfg(feature = "test-support")]
const _: () = assert!(SELECTED.evidence == crate::test_support::R1_EVIDENCE_RECORD_CAPACITY);
// Deliberately below E8's 64-handle tables. E8's widened per-Process pools are
// why its termination path needed a 4 MiB per-thread stack; this product's
// demand does not require them, and plan section 12 forbids growing a
// multi-megabyte kernel stack in place of reducing giant frames.
const _: () = assert!(SELECTED.handles < 64);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::handle::{HandleTable, HandleTableError};
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::{DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT};

    #[test]
    fn selector34_r1_selected_marker_matches_executable_capacities() {
        let marker = std::format!(
            "// R1_SELECTED_CAPACITIES per_process_handle_capacity={} memory_object_capacity={} mapping_lease_capacity={} registry_object_capacity={}",
            SELECTED.handles,
            SELECTED.memory,
            SELECTED.mappings,
            SELECTED.registry,
        );
        assert_eq!(
            include_str!("r1_resource_geometry.rs")
                .lines()
                .filter(|line| *line == marker)
                .count(),
            1
        );
    }

    #[test]
    fn selector34_r1_peaks_are_the_documented_arithmetic() {
        assert_eq!(INIT_BASELINE_HANDLES, 14);
        assert_eq!(ZERO_STREAM_LOADER_HANDLES, 7);
        assert_eq!(HANDLE_PEAK, 37);
        assert_eq!(BASELINE_MEMORY, 13);
        assert_eq!(MEMORY_PEAK, 32);
        assert_eq!(MAPPING_PEAK, 32);
        assert_eq!(LIVE_PROCESSES, 13);
        assert_eq!(LIVE_TASK_GROUPS, 14);
        assert_eq!(BASELINE_CHANNEL_PAIRS, 9);
        assert_eq!(CHANNEL_PAIR_PEAK, 18);
        assert_eq!(CHANNEL_ENDPOINT_PEAK, 28);
        assert_eq!(REGISTRY_PEAK, 115);
        assert_eq!(WAIT_PEAK, 30);
        assert_eq!(BOOTFS_ENTRY_PEAK, 15);
        const { assert!(BOOTFS_ENTRY_PEAK < BOOTFS_ENTRY_CAPACITY) };
        assert_eq!(
            (
                EVIDENCE_CONTROL_PEAK,
                EVIDENCE_SMP_PEAK,
                EVIDENCE_CEILING_PEAK
            ),
            (20, 38, 50)
        );
    }

    // The ceiling is what the capacity must satisfy; prove the two selected
    // plans sit strictly inside it so neither can silently exceed the pools.
    #[test]
    fn selector34_r1_selected_plans_fit_inside_the_sized_ceiling() {
        const {
            assert!(SMP_PLAN_HOGS <= MAX_HOGS);
            assert!(CONTROL_PLAN_HOGS < SMP_PLAN_HOGS);
            assert!(EVIDENCE_SMP_PEAK < EVIDENCE_CEILING_PEAK);
            assert!(EVIDENCE_CEILING_PEAK <= SELECTED.evidence);
        }
        for hogs in [CONTROL_PLAN_HOGS, SMP_PLAN_HOGS, MAX_HOGS] {
            let handles = INIT_BASELINE_HANDLES + hogs * 2 + ZERO_STREAM_LOADER_HANDLES;
            let memory = BASELINE_MEMORY + hogs * HOG_IMAGE_OBJECTS + PROGRESS_IMAGE_OBJECTS;
            assert!(handles <= HANDLE_PEAK);
            assert!(memory <= MEMORY_PEAK);
            assert!(hogs * STEPS_PER_HOG + 2 <= SELECTED.evidence);
        }
    }

    #[test]
    fn selector34_r1_lifetime_census_counts_retired_generations_once() {
        for (index, identity) in LIFETIME_IDENTITIES.iter().enumerate() {
            assert!(!LIFETIME_IDENTITIES[..index].contains(identity));
        }
        // Primordial, four residents, and one hog plus one progress child per
        // hog at the ceiling.
        assert_eq!(
            LIFETIME_IDENTITIES.len(),
            1 + RESIDENT_IMAGES + 2 * MAX_HOGS
        );
        assert_eq!(LIFETIME_IDENTITIES.len(), 21);
        // The census exceeds every identity pool on purpose, and that must not
        // read as an undersized ledger: it counts retired generations, which
        // hold no slot. A capacity one below the *simultaneous* peak is the
        // thing that fails.
        assert!(LIFETIME_IDENTITIES.len() > SELECTED.identities);
        assert!(fits(Capacity {
            identities: LIVE_IDENTITY_PEAK,
            ..SELECTED
        }));
        assert!(!fits(Capacity {
            identities: LIVE_IDENTITY_PEAK - 1,
            ..SELECTED
        }));
        assert!(fits(SELECTED));
    }

    // The inherited default pools must fail on their own arithmetic, not by
    // symbolic comparison with the chosen values. These are the exact
    // bootstrap-era constants selector 34 silently used before this ledger.
    #[test]
    fn selector34_r1_inherited_default_pools_fail_every_bottleneck() {
        for smaller in [
            Capacity {
                handles: 10,
                ..SELECTED
            },
            Capacity {
                memory: 10,
                ..SELECTED
            },
            Capacity {
                mappings: 10,
                ..SELECTED
            },
            Capacity {
                identities: 3,
                ..SELECTED
            },
            Capacity {
                registry: 32,
                ..SELECTED
            },
            Capacity {
                channel_pairs: 3,
                ..SELECTED
            },
            Capacity {
                waits: 4,
                ..SELECTED
            },
        ] {
            assert!(!fits(smaller));
        }
        assert!(fits(SELECTED));
    }

    // Every pool is independently one short of its own peak, so a capacity
    // correction cannot pass by over-provisioning an unrelated pool.
    #[test]
    fn selector34_r1_each_pool_is_exactly_binding_at_its_peak() {
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
            Capacity {
                evidence: EVIDENCE_CEILING_PEAK - 1,
                ..SELECTED
            },
        ] {
            assert!(!fits(smaller));
        }
        // Each peak exactly met, with no headroom anywhere, still fits.
        assert!(fits(Capacity {
            handles: HANDLE_PEAK,
            memory: MEMORY_PEAK,
            mappings: MAPPING_PEAK,
            identities: LIVE_IDENTITY_PEAK,
            registry: REGISTRY_PEAK,
            channel_pairs: CHANNEL_PAIR_PEAK,
            waits: WAIT_PEAK,
            evidence: EVIDENCE_CEILING_PEAK,
        }));
    }

    fn admit_memory<const OBJECTS: usize>(demand: usize) -> usize {
        use crate::memory::frame_roles::synthetic_allocator_backing;
        use crate::memory::object::{
            MemoryObjectAuthority, MemoryObjectError, MemoryObjectKind, MemoryProtection,
        };
        use deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT;
        let mut registry = ObjectRegistry::<64>::new();
        let mut memory = MemoryObjectAuthority::<OBJECTS, 64>::new();
        let mut owners = std::vec::Vec::new();
        for index in 0..demand {
            let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
            let backing = synthetic_allocator_backing(0x20_000 + index as u64 * 0x1000, 1);
            match memory.grant_backing(
                &creation,
                backing,
                4096,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ,
            ) {
                Ok(_) => owners.push(registry.creation_into_internal(creation).unwrap()),
                Err(failure) => {
                    assert_eq!(failure.error(), MemoryObjectError::Capacity);
                    let _backing = failure.into_backing();
                    registry.cancel_creation(creation).unwrap();
                    break;
                }
            }
        }
        let admitted = owners.len();
        for owner in owners {
            let release = registry.release_internal(owner).unwrap().unwrap();
            let (release, _backing) = memory.take_finalization(release).unwrap().into_parts();
            registry.complete_finalization(release).unwrap();
        }
        admitted
    }

    // Exercise the real MemoryObject authority, not just the ledger. The
    // inherited ten-object pool exhausts partway through the resident graph,
    // before a single hog is launched.
    #[test]
    fn selector34_r1_real_memory_pool_rejects_the_inherited_ten_object_default() {
        assert_eq!(admit_memory::<10>(MEMORY_PEAK), 10);
        const { assert!(BASELINE_MEMORY > 10) };
        assert_eq!(
            admit_memory::<{ SELECTED.memory }>(MEMORY_PEAK),
            MEMORY_PEAK
        );
    }

    fn admit_handles<const HANDLES: usize>(demand: usize) -> usize {
        let mut objects = ObjectRegistry::<64>::new();
        let mut handles = HandleTable::<HANDLES>::new();
        let mut admitted = 0;
        for _ in 0..demand {
            let object = objects.create(DW_OBJECT_TYPE_CHANNEL).unwrap();
            let reference = objects.creation_into_handle(object).unwrap();
            match handles.install(reference, DW_RIGHT_INSPECT) {
                Ok(_) => admitted += 1,
                Err(failure) => {
                    assert_eq!(failure.error(), HandleTableError::Capacity);
                    let release = objects
                        .release_handle(failure.into_reference())
                        .unwrap()
                        .unwrap();
                    objects.complete_finalization(release).unwrap();
                    break;
                }
            }
        }
        for release in handles
            .drain(&mut objects)
            .into_final_releases()
            .into_iter()
            .flatten()
        {
            objects.complete_finalization(release).unwrap();
        }
        admitted
    }

    // Exercise real per-Process handle admission. The inherited ten-handle
    // table cannot even hold init's resident baseline, so the first dynamic
    // launch is impossible; the selected table admits the full peak.
    #[test]
    fn selector34_r1_real_handle_table_rejects_the_inherited_ten_slot_default() {
        const { assert!(INIT_BASELINE_HANDLES > 10) };
        assert_eq!(admit_handles::<10>(HANDLE_PEAK), 10);
        let first_hog_launch =
            INIT_BASELINE_HANDLES + HOG_RETAINED_HANDLES + ZERO_STREAM_LOADER_HANDLES;
        assert_eq!(first_hog_launch, 23);
        assert_eq!(admit_handles::<22>(first_hog_launch), 22);
        assert_eq!(
            admit_handles::<{ SELECTED.handles }>(HANDLE_PEAK),
            HANDLE_PEAK
        );
    }

    #[test]
    fn selector34_r1_registry_census_fits_the_selected_pool() {
        use deepwyrm_abi::{
            DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_DEVICE_RESOURCE,
            DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP,
            DW_OBJECT_TYPE_THREAD, DW_OBJECT_TYPE_TIMER,
        };
        let census = [
            (DW_OBJECT_TYPE_PROCESS, LIVE_PROCESSES),
            (DW_OBJECT_TYPE_THREAD, LIVE_PROCESSES),
            (DW_OBJECT_TYPE_ADDRESS_REGION, LIVE_PROCESSES),
            (DW_OBJECT_TYPE_TASK_GROUP, LIVE_TASK_GROUPS),
            (DW_OBJECT_TYPE_MEMORY_OBJECT, MEMORY_PEAK),
            (DW_OBJECT_TYPE_CHANNEL, CHANNEL_ENDPOINT_PEAK),
            (DW_OBJECT_TYPE_DEVICE_RESOURCE, DEVICE_RESOURCES),
            (DW_OBJECT_TYPE_TIMER, TIMER_PEAK),
        ];
        fn admit<const N: usize>(census: &[(deepwyrm_abi::DwObjectType, usize)]) -> usize {
            let mut registry = ObjectRegistry::<N>::new();
            let mut objects = std::vec::Vec::new();
            'census: for &(kind, count) in census {
                for _ in 0..count {
                    match registry.create(kind) {
                        Ok(object) => objects.push(object),
                        Err(error) => {
                            assert_eq!(error, crate::object::ObjectRegistryError::Capacity);
                            break 'census;
                        }
                    }
                }
            }
            let admitted = objects.len();
            for object in objects {
                registry.cancel_creation(object).unwrap();
            }
            admitted
        }
        // The census sums to exactly the ledger's peak, and the inherited
        // 32-object default truncates it long before the hogs appear.
        assert_eq!(
            census.iter().map(|entry| entry.1).sum::<usize>(),
            REGISTRY_PEAK
        );
        assert_eq!(admit::<32>(&census), 32);
        assert_eq!(admit::<{ REGISTRY_PEAK }>(&census), REGISTRY_PEAK);
        assert_eq!(admit::<{ SELECTED.registry }>(&census), REGISTRY_PEAK);
    }
}

#[cfg(test)]
mod thread_arena {
    use super::*;

    /// The regression this ledger's first selection shipped.
    ///
    /// A selection above the linked arena is not caught by any run-time bound;
    /// it removes the whole runtime from the release artifact. So the ledger
    /// asserts the ceiling in `const` context, and this test states what the
    /// ceiling is and that the selection has real headroom under it.
    #[test]
    fn selector34_r1_identity_capacity_stays_inside_the_linked_thread_arena() {
        const ARENA: usize = crate::memory::kernel_stack::E3_THREAD_STACK_COUNT;
        assert_eq!(ARENA, 16);
        const {
            assert!(SELECTED.identities <= ARENA);
            // The simultaneous peak must fit with room to spare, or the next
            // actor the scenario gains would push the ledger straight back over.
            assert!(LIVE_IDENTITY_PEAK < ARENA);
        }
        assert_eq!(LIVE_IDENTITY_PEAK, 14);
        assert_eq!(LIVE_PROCESSES, 13);
        assert_eq!(LIVE_TASK_GROUPS, 14);
    }

    /// Every identity-indexed pool must be the same number, because they are
    /// all one occupancy bound wearing different names in `primordial.rs`. A
    /// split between them would let one overflow while the ledger proved the
    /// others.
    #[test]
    fn selector34_r1_identity_peak_covers_both_live_counts() {
        const {
            assert!(LIVE_IDENTITY_PEAK >= LIVE_PROCESSES);
            assert!(LIVE_IDENTITY_PEAK >= LIVE_TASK_GROUPS);
            // Sized from the eight-hog ceiling, not the six-hog SMP plan, so a
            // plan change cannot silently require a kernel capacity change.
            assert!(LIVE_PROCESSES > RESIDENT_IMAGES + SMP_PLAN_HOGS + 1);
        }
        assert_eq!(LIVE_PROCESSES, RESIDENT_IMAGES + MAX_HOGS + 1);
    }
}
