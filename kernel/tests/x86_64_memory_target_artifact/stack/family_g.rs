use super::*;

/// The live family-G facade path (D1 option B3 and commit 9): map, unmap and
/// protect run through `RuntimeCarrierFacade::handle_address_region_mutation`,
/// which owns the transaction's `HeldReleases` (a whole cleanup queue, about
/// 5 KiB) in its frame across the acknowledgement wait. DW1C's trace-bound
/// chain predates that helper and no longer covers this path, so it is bound
/// here from the emitted artifact.
///
/// The chain is the ordinary syscall entry up to the facade's handler (the
/// trampoline calls the dispatch frame when it is emitted), then the
/// emitted frames of the deepest known family-G path, from the helper to
/// the coherent AddressRegion commit (map, the deepest of the three). Like
/// DW1C's, it is a trace-bound upper bound asserted against the linked
/// Thread stack with the required spare, not an exact equality.
pub(crate) fn validate_family_g_facade_stack_margin(
    sizes: &[StackSize],
    disassembly: &str,
    thread_stack_bytes: usize,
    product: &str,
) {
    const RAW_SYSCALL_FRAME_BYTES: usize = 144;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const HELD_RELEASES_FLOOR_BYTES: usize = 4 * 1024;

    let select = |description: &str, predicate: &dyn Fn(&str) -> bool| {
        let symbol = one_stack_symbol(sizes, description, predicate);
        let bytes = one_stack_size(sizes, description, |candidate| candidate == symbol);
        (symbol, bytes)
    };
    let (_, syscall_dispatch_bytes) = select("family-G syscall dispatcher", &|symbol| {
        symbol == "dw_x86_64_syscall_dispatch"
    });
    let (_, bound_dispatch_bytes) = select("family-G bound dispatcher", &|symbol| {
        symbol.ends_with("arch::x86_64::syscall::live::dispatch_bound_runtime")
    });
    let (runtime_trampoline, runtime_trampoline_bytes) =
        select("family-G runtime trampoline", &|symbol| {
            symbol.contains("arch::x86_64::syscall::live::native_runtime_trampoline::<")
                && symbol.contains("RuntimeCarrierFacade<128, 4096>")
                && !symbol.contains("::{closure")
        });
    let dispatch_frame = sizes
        .iter()
        .any(|size| {
            size.symbol.contains("syscall::native::dispatch_frame::<")
                && size.symbol.contains("RuntimeCarrierFacade<128, 4096>")
                && !size.symbol.contains("::{closure")
        })
        .then(|| {
            select("family-G dispatch frame", &|symbol| {
                symbol.contains("syscall::native::dispatch_frame::<")
                    && symbol.contains("RuntimeCarrierFacade<128, 4096>")
                    && !symbol.contains("::{closure")
            })
        });
    let (runtime_handler, runtime_handler_bytes) = select("family-G runtime handler", &|symbol| {
        symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && symbol
                .ends_with("as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle")
    });
    let is_helper = |symbol: &str| {
        symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && symbol.ends_with(">::handle_address_region_mutation")
    };
    let (_, helper_bytes) = select("family-G facade helper", &is_helper);
    assert!(
        helper_bytes >= HELD_RELEASES_FLOOR_BYTES,
        "{product} family-G helper frame ({helper_bytes}) no longer holds its HeldReleases"
    );

    match &dispatch_frame {
        Some((dispatch_frame, _)) => {
            assert!(
                function_body(disassembly, &runtime_trampoline)
                    .contains(&format!(" <{dispatch_frame}>"))
            );
            assert!(
                function_body(disassembly, dispatch_frame)
                    .contains(&format!(" <{runtime_handler}>"))
            );
        }
        None => assert!(
            function_body(disassembly, &runtime_trampoline)
                .contains(&format!(" <{runtime_handler}>"))
        ),
    }
    // The handler's routing chain names the helper (pinned from source by
    // `family_g_waits_for_acknowledgement_outside_the_hold`). In this artifact
    // the helper has no direct call site in the objdump text (its address
    // appears only in its own header), so the edge is taken from that source
    // pin and the helper's subtree is bound from its own emitted frame down.
    // A whole-subtree direct-call bound from the helper does not close: the
    // map path reaches register-indirect jump tables the shared parser does
    // not recognize, and this artifact calls the helper and its first hold
    // through RIP-relative table slots (`call qword ptr [rip + ..] # <anon..>`)
    // that the objdump does not name. So the bound is trace-bound, as DW1C's
    // is: the frames of the deepest known path, from the helper down to the
    // coherent AddressRegion commit, each counted with its return word when
    // it is emitted on its own. A frame that is inlined into its caller has
    // no entry and adds nothing. Summing every emitted frame of the path is
    // an upper bound however they nest.
    type FramePredicate<'a> = &'a dyn Fn(&str) -> bool;
    let path_candidates: [(&str, FramePredicate<'_>); 6] = [
        ("first family-G hold", &|symbol: &str| {
            symbol.contains("PrimordialRuntimeCarrier<128, 4096>>::begin_address_region_mutation")
                && !symbol.contains("::{closure")
        }),
        ("map", &|symbol: &str| {
            symbol.contains("PrimordialRuntimeCarrier<128, 4096>>::map_memory")
                && !symbol.contains("::{closure")
        }),
        ("prepared map adapter", &|symbol: &str| {
            symbol
                .contains("syscall::adapters::address_region::address_region_map_prepared_model::<")
                && symbol.contains("CoherentAddressSpacePublisher<")
        }),
        ("map adapter", &|symbol: &str| {
            symbol.contains("syscall::adapters::address_region::address_region_map_model::<")
                && symbol.contains("CoherentAddressSpacePublisher<")
        }),
        ("AddressRegion map", &|symbol: &str| {
            symbol.contains("AddressRegion<10>>::map_anywhere::<")
                && symbol.contains("CoherentAddressSpacePublisher<")
        }),
        ("coherent AddressRegion commit", &|symbol: &str| {
            symbol.contains("AddressRegion<10>>::commit_specs::<40, 40, 256,")
                && symbol.contains("CoherentAddressSpacePublisher<")
                && symbol.contains("TrackedActiveTarget, 128, 4096, 6, 59, 53>")
                && symbol.contains("LiveTlbShootdownDriver")
        }),
    ];
    let mut path_bytes = helper_bytes;
    let mut path_calls = 0_usize;
    let mut path = vec!["facade helper"];
    for (name, predicate) in path_candidates {
        let emitted = sizes.iter().filter(|size| predicate(&size.symbol)).count();
        assert!(
            emitted <= 1,
            "{product} family-G {name} has {emitted} emitted instances"
        );
        if emitted == 0 {
            continue;
        }
        let (_, bytes) = select(name, predicate);
        path_bytes += bytes;
        path_calls += 1;
        path.push(name);
    }
    for required in ["map", "coherent AddressRegion commit"] {
        assert!(
            path.contains(&required),
            "{product} family-G path lost its emitted {required} frame: {path:?}"
        );
    }

    let prefix_frames = [
        syscall_dispatch_bytes,
        bound_dispatch_bytes,
        runtime_trampoline_bytes,
        dispatch_frame.as_ref().map_or(0, |(_, bytes)| *bytes),
        runtime_handler_bytes,
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .expect("family-G prefix frames fit usize");
    // The entry calls the dispatcher; the dispatcher calls the bound runtime,
    // which tail-jumps; the trampoline calls the (emitted) dispatch frame and
    // the handler; the handler calls the helper.
    let prefix_returns = (3 + usize::from(dispatch_frame.is_some())) * size_of::<u64>();
    let total = RAW_SYSCALL_FRAME_BYTES
        .checked_add(prefix_frames)
        .and_then(|bytes| bytes.checked_add(prefix_returns))
        .and_then(|bytes| bytes.checked_add(path_bytes))
        .and_then(|bytes| bytes.checked_add(path_calls * size_of::<u64>()))
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("family-G stack bound fits usize");
    eprintln!(
        "{product} family-G facade thread-stack bound={total} helper-frame={helper_bytes} \
         path-frames={path_bytes} path={path:?} linked={thread_stack_bytes} remaining={}",
        thread_stack_bytes.saturating_sub(total)
    );
    assert!(
        total + REQUIRED_SPARE_BYTES <= thread_stack_bytes,
        "{product} family-G facade path exceeds the linked Thread stack: total={total} \
         required-spare={REQUIRED_SPARE_BYTES} linked={thread_stack_bytes}"
    );
}
