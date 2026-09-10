//! Selector-33 E8 scenario demand, separate from production resource policy.
//!
//! This is a source/host capacity model, not live acceptance. Image geometry
//! comes from the exact E8 product: resident images and hello have two PT_LOAD
//! segments; zero-stream hogs have one. The loader owns one object per segment
//! and one stack object. It unmaps its scratch view before mapping the child.
//! Changes to the selected product or its ownership graph require reconciling
//! this ledger with WYR1_E8_RECOVERY_CONTRACT section 8 and product preflight.

// Enumerate every lifetime identity, including finalized generations. E8 does
// not select the DW1C/D sticky terminal-history storage: this census is a
// conservative task-family sizing envelope, not thirty concurrently live
// registry graphs. Rejected/malformed launches never publish a Process.
pub(super) const LIFETIME_IDENTITIES: [&str; 30] = [
    "primordial",
    "system-init",
    "devmgr",
    "registry-1",
    "registry-2",
    "uart-1",
    "uart-2",
    "consoled-1",
    "consoled-2",
    "consoled-3",
    "shell-s1",
    "shell-s2",
    "shell-s3",
    "shell-s4",
    "s1-hello",
    "s1-nonzero",
    "s1-fault",
    "s1-hog",
    "s2-driver-trigger",
    "s3-registry-trigger",
    "s4-hog-1",
    "s4-hog-2",
    "s4-hog-3",
    "s4-hog-4",
    "s4-hog-5",
    "s4-hog-6",
    "s4-hello-1",
    "s4-hello-2",
    "s4-hello-3",
    "s4-pressure",
];

// init's four authorities; registry Process/TaskGroup/bootstrap/control; devmgr
// Process/bootstrap/publication; UART Process/bootstrap/control; consoled
// Process/bootstrap/registry/launch; outer shell Process/TaskGroup/job endpoint.
const INIT_RESIDENT_HANDLES: [usize; 6] = [4, 4, 3, 3, 4, 3];
pub(super) const INIT_BASELINE_HANDLES: usize = sum(&INIT_RESIDENT_HANDLES);
const HOG_RETAINED_HANDLES: usize = 2; // Process and TaskGroup; no stream handles.
const RESIDENT_IMAGES: usize = 6;
const RESIDENT_IMAGE_OBJECTS: usize = 2 + 1; // PT_LOADs plus initial stack.
pub(super) const BASELINE_MEMORY: usize = RESIDENT_IMAGES * RESIDENT_IMAGE_OBJECTS + 1;
pub(super) const S4_HOGS: usize = 6;

// Loader stages are additive to the caller's existing handles and one new
// attempt TaskGroup. Stream INIT staging retains at most three transferred
// endpoints. Scratch memory closes before ThreadCreate. ChannelReduce briefly
// needs the broad and reduced parent handles together with the child endpoint.
pub(super) const CHANNEL_REDUCE_HANDLES: usize = 1 + 2 + 1;
const STREAM_JOB_LOADER_HANDLES: usize = 1 + 3 + 1 + 2 + 1;
pub(super) const HANDLE_PEAK: usize =
    INIT_BASELINE_HANDLES + S4_HOGS * HOG_RETAINED_HANDLES + STREAM_JOB_LOADER_HANDLES;
pub(super) const MEMORY_PEAK: usize = BASELINE_MEMORY + S4_HOGS * (1 + 1) + (2 + 1);
pub(super) const MAPPING_PEAK: usize = MEMORY_PEAK;

// The live S4 graph contains six residents, six hogs and one responsiveness
// hello. Registry slots are reusable after typed finalization; scheduler
// lifetime identity census is not thirty simultaneously retained registry graphs.
pub(super) const LIVE_PROCESSES: usize = RESIDENT_IMAGES + S4_HOGS + 1;
pub(super) const LIVE_TASK_GROUPS: usize = LIVE_PROCESSES + 1;
// Baseline includes seventeen pairs but only thirty-two endpoint objects:
// some startup peers have already closed. A hog need not yet have observed
// parent peer-close, so each of the six hogs may retain its one-sided startup
// pair. Hello adds three stream pairs and one startup pair (eight endpoints).
pub(super) const CHANNEL_PAIR_PEAK: usize = 17 + S4_HOGS + 3 + 1;
pub(super) const CHANNEL_ENDPOINT_PEAK: usize = 32 + S4_HOGS + 2 * (3 + 1);
pub(super) const REGISTRY_PEAK: usize = LIVE_PROCESSES * 3 // Process, Thread, root
    + LIVE_TASK_GROUPS + MEMORY_PEAK + CHANNEL_ENDPOINT_PEAK
    + 1 + 1 + 1; // DeviceResource, Interrupt, UART pacing Timer
// Both timers can overlap at boot/recovery; that smaller graph is bounded
// separately below, rather than silently omitting the controller tick Timer.
pub(super) const TIMER_PEAK: usize = 2;
pub(super) const EVENT_PEAK: usize = 0;
pub(super) const REGION_MAPPING_PEAK: usize = 2 + 1 + 1 + 1; // PT_LOADs, stack, bootfs, scratch
// Startup/transition envelope allows eight images (including primordial or a
// trigger/replacement under construction), nine groups, the full S4 endpoint
// envelope and both control/UART timers. Reaping/quiescence prevents old and
// new recovery generations from accumulating; this upper bound is 108.
pub(super) const TRANSITION_REGISTRY_BOUND: usize =
    8 * 3 + 9 + (8 * 3 + 1) + CHANNEL_ENDPOINT_PEAK + 1 + 1 + TIMER_PEAK;
pub(super) const WAIT_PEAK: usize = 13 + 3 + 4 + 6 + 7 + 7 + 1;
// Wyrmroot owns the archive parser, whose selected record limit is 4096.
// E8 is the ten-entry C1 base plus policy and seven actor files, including
// the malformed-ELF negative input. No extra kernel object is made per entry.
pub(super) const BOOTFS_ENTRY_PEAK: usize = 10 + 1 + 7;
pub(super) const BOOTFS_ENTRY_CAPACITY: usize = 4096;
pub(super) const EVIDENCE_UP_PEAK: usize = 20 + 3 + 3 + 7;
pub(super) const EVIDENCE_SMP_PEAK: usize = 20 + 3 + 3 + 43;

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

// WYR1E8_SELECTED_CAPACITIES per_process_handle_capacity=64 memory_object_capacity=64 mapping_lease_capacity=64 registry_object_capacity=160
pub(super) const SELECTED: Capacity = Capacity {
    handles: 64,
    memory: 64,
    mappings: 64,
    identities: 64,
    registry: 160,
    channel_pairs: 32,
    waits: 64,
    evidence: 128,
};

// The old profile fails both independent bottlenecks, not merely a symbolic
// comparison with the chosen 64. S4 responsiveness actors are sequential;
// pressure runs only after all six hogs have been reaped and closed.
pub(super) const fn fits(capacity: Capacity) -> bool {
    capacity.handles >= HANDLE_PEAK
        && capacity.memory >= MEMORY_PEAK
        && capacity.mappings >= MAPPING_PEAK
        && capacity.identities >= LIFETIME_IDENTITIES.len()
        && capacity.registry >= REGISTRY_PEAK
        && capacity.channel_pairs >= CHANNEL_PAIR_PEAK
        && capacity.waits >= WAIT_PEAK
        && capacity.evidence >= EVIDENCE_SMP_PEAK
}

const _: () = assert!(fits(SELECTED));
const _: () = assert!(TRANSITION_REGISTRY_BOUND <= REGISTRY_PEAK);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::handle::{HandleTable, HandleTableError};
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::{DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT};

    #[test]
    fn selector33_e8_selected_marker_matches_executable_capacities() {
        let marker = std::format!(
            "// WYR1E8_SELECTED_CAPACITIES per_process_handle_capacity={} memory_object_capacity={} mapping_lease_capacity={} registry_object_capacity={}",
            SELECTED.handles,
            SELECTED.memory,
            SELECTED.mappings,
            SELECTED.registry,
        );
        assert_eq!(
            include_str!("wyr1e8_resource_geometry.rs")
                .lines()
                .filter(|line| *line == marker)
                .count(),
            1
        );
    }

    // Each checkpoint is reached in order. Replacements are admitted only
    // after old dependent retirement; the held trigger WAIT is joined before
    // that quiescence boundary. Startup includes primordial until it exits.
    #[test]
    fn selector33_e8_full_scenario_memory_lifecycle() {
        let mut objects = 1; // shared bootfs
        let mut peak = objects;
        let mut identities = 0;
        let mut admit = |count: &mut usize, image_objects: usize| {
            *count += image_objects;
            identities += 1;
            peak = peak.max(*count);
        };
        admit(&mut objects, 3); // primordial
        for _ in 0..6 {
            admit(&mut objects, 3);
        } // full initial service/shell graph
        objects -= 3; // primordial retirement
        assert_eq!(objects, BASELINE_MEMORY);
        for image_objects in [3, 2, 2, 2] {
            // S1 hello/nonzero/fault/hog
            admit(&mut objects, image_objects);
            objects -= image_objects;
        }
        objects -= 3; // S1 shell exit
        admit(&mut objects, 3); // S2 shell
        admit(&mut objects, 2); // driver trigger, held WAIT
        objects -= 2; // WAIT joined and trigger reaped
        objects -= 3 * 3; // shell, consoled, UART retired before replacements
        for _ in 0..3 {
            admit(&mut objects, 3);
        } // UART2, consoled2, S3 shell
        admit(&mut objects, 2); // registry trigger, held WAIT
        objects -= 2;
        objects -= 3 * 3; // shell, consoled, registry retired; UART stays healthy
        for _ in 0..3 {
            admit(&mut objects, 3);
        } // registry2, consoled3, S4 shell
        assert_eq!(objects, BASELINE_MEMORY);
        for _ in 0..S4_HOGS {
            admit(&mut objects, 2);
        }
        assert_eq!(objects, 31);
        for _ in 0..3 {
            admit(&mut objects, 3); // fixed S4 responsiveness hello cycle
            objects -= 3; // WAIT/CLOSE before the next cycle
        }
        objects -= S4_HOGS * 2; // TERMINATE/WAIT/CLOSE all hogs
        admit(&mut objects, 2); // pressure after hog cleanup
        objects -= 2;
        objects -= 3; // final shell retirement
        assert_eq!(objects, BASELINE_MEMORY - 3);
        assert_eq!(identities, LIFETIME_IDENTITIES.len());
        assert_eq!(peak, MEMORY_PEAK);
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

    #[test]
    fn selector33_e8_real_memory_pool_reproduces_fifth_hog_stack_exhaustion() {
        // Four hogs consume eight additional objects. The fifth segment is
        // object28 and its stack requests object29, even with handles repaired.
        assert_eq!(BASELINE_MEMORY + 4 * 2 + 1, 28);
        assert_eq!(admit_memory::<28>(29), 28);
        assert_eq!(
            admit_memory::<{ SELECTED.memory }>(MEMORY_PEAK),
            MEMORY_PEAK
        );
    }

    #[test]
    fn selector33_e8_lifetime_census_counts_retired_generations_once() {
        for (index, identity) in LIFETIME_IDENTITIES.iter().enumerate() {
            assert!(!LIFETIME_IDENTITIES[..index].contains(identity));
        }
        assert_eq!(LIFETIME_IDENTITIES.len(), 30);
        assert!(!fits(Capacity {
            identities: 29,
            ..SELECTED
        }));
        assert!(fits(SELECTED));
    }

    #[test]
    fn selector33_e8_independent_old_pools_fail_and_selected_bounds_pass() {
        assert_eq!(INIT_BASELINE_HANDLES, 21);
        assert_eq!(BASELINE_MEMORY, 19);
        assert_eq!(HANDLE_PEAK, 41);
        assert_eq!(MEMORY_PEAK, 34);
        assert_eq!(MAPPING_PEAK, 34);
        assert!(!fits(Capacity {
            handles: 32,
            ..SELECTED
        }));
        assert!(!fits(Capacity {
            memory: 28,
            ..SELECTED
        }));
        assert!(!fits(Capacity {
            mappings: 28,
            ..SELECTED
        }));
        assert!(!fits(Capacity {
            handles: 40,
            ..SELECTED
        }));
        assert!(!fits(Capacity {
            memory: 33,
            ..SELECTED
        }));
        assert!(!fits(Capacity {
            mappings: 33,
            ..SELECTED
        }));
        assert!(fits(SELECTED));
    }

    #[test]
    fn selector33_e8_other_selected_pools_are_recomputed() {
        assert_eq!(LIVE_PROCESSES, 13);
        assert_eq!(LIVE_TASK_GROUPS, 14);
        assert_eq!(CHANNEL_PAIR_PEAK, 27);
        assert_eq!(CHANNEL_ENDPOINT_PEAK, 46);
        assert_eq!(REGISTRY_PEAK, 136);
        assert_eq!(TRANSITION_REGISTRY_BOUND, 108);
        assert_eq!(WAIT_PEAK, 41);
        assert_eq!(BOOTFS_ENTRY_PEAK, 18);
        const { assert!(BOOTFS_ENTRY_PEAK < BOOTFS_ENTRY_CAPACITY) };
        assert_eq!((EVIDENCE_UP_PEAK, EVIDENCE_SMP_PEAK), (33, 69));
        for smaller in [
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
                evidence: EVIDENCE_SMP_PEAK - 1,
                ..SELECTED
            },
        ] {
            assert!(!fits(smaller));
        }
        assert!(fits(SELECTED));
    }

    #[test]
    fn selector33_e8_registry_endpoint_and_payload_census_fits_real_pool() {
        use deepwyrm_abi::{
            DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_DEVICE_RESOURCE,
            DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_PROCESS,
            DW_OBJECT_TYPE_TASK_GROUP, DW_OBJECT_TYPE_THREAD, DW_OBJECT_TYPE_TIMER,
        };
        let census = [
            (DW_OBJECT_TYPE_PROCESS, LIVE_PROCESSES),
            (DW_OBJECT_TYPE_THREAD, LIVE_PROCESSES),
            (DW_OBJECT_TYPE_ADDRESS_REGION, LIVE_PROCESSES),
            (DW_OBJECT_TYPE_TASK_GROUP, LIVE_TASK_GROUPS),
            (DW_OBJECT_TYPE_MEMORY_OBJECT, MEMORY_PEAK),
            (DW_OBJECT_TYPE_CHANNEL, CHANNEL_ENDPOINT_PEAK),
            (DW_OBJECT_TYPE_DEVICE_RESOURCE, 1),
            (DW_OBJECT_TYPE_INTERRUPT, 1),
            (DW_OBJECT_TYPE_TIMER, 1),
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
        assert_eq!(admit::<135>(&census), 135);
        assert_eq!(admit::<{ SELECTED.registry }>(&census), REGISTRY_PEAK);
    }

    // Exercise actual kernel handle admission at the historical fifth-hog
    // ChannelReduce slot 33 and at the full streamed-hello high-water mark.
    // Object type is irrelevant to this per-Process slot quota; use one type
    // here and leave typed lifecycle semantics to the existing object tests.
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

    #[test]
    fn selector33_e8_real_handle_table_reproduces_fifth_hog_exhaustion() {
        let fifth_hog_reduce =
            INIT_BASELINE_HANDLES + 4 * HOG_RETAINED_HANDLES + CHANNEL_REDUCE_HANDLES;
        assert_eq!(fifth_hog_reduce, 33);
        assert_eq!(admit_handles::<32>(fifth_hog_reduce), 32);
        assert_eq!(
            admit_handles::<{ SELECTED.handles }>(HANDLE_PEAK),
            HANDLE_PEAK
        );
    }
}
