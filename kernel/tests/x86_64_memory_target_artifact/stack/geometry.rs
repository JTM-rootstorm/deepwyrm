use super::*;

pub(crate) fn validate_kernel_stack_artifact_geometry(symbols: &str) {
    let addresses = symbols
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            Some((fields.next()?, address))
        })
        .collect::<BTreeMap<_, _>>();
    let address = |name: &str| {
        *addresses
            .get(name)
            .unwrap_or_else(|| panic!("production artifact omitted kernel-stack symbol {name}"))
    };
    let boot_bottom = address("__dw_boot_stack_bottom");
    let boot_top = address("__dw_boot_stack_top");
    assert_eq!(boot_bottom & 0xfff, 0, "boot stack alignment");
    assert_eq!(boot_top - boot_bottom, 256 * 1024);
    assert!(
        address("__dw_data_start") <= boot_bottom && boot_top <= address("__dw_data_end"),
        "linked boot stack escapes the writable data PT_LOAD bounds"
    );
    let stacks = [
        (
            "__dw_double_fault_ist_guard",
            "__dw_double_fault_ist_bottom",
            "__dw_double_fault_ist_top",
        ),
        (
            "__dw_nmi_ist_guard",
            "__dw_nmi_ist_bottom",
            "__dw_nmi_ist_top",
        ),
        (
            "__dw_machine_check_ist_guard",
            "__dw_machine_check_ist_bottom",
            "__dw_machine_check_ist_top",
        ),
    ];
    for (guard, bottom, top) in stacks {
        assert_eq!(address(guard) & 0xfff, 0, "{guard} is not page aligned");
        assert_eq!(address(bottom) - address(guard), 4096, "{guard} size");
        assert_eq!(address(top) - address(bottom), 16 * 1024, "{top} size");
    }
    assert_eq!(
        address("__dw_ist_region_start"),
        address("__dw_double_fault_ist_guard")
    );
    assert_eq!(
        address("__dw_double_fault_ist_top"),
        address("__dw_nmi_ist_guard")
    );
    assert_eq!(
        address("__dw_nmi_ist_top"),
        address("__dw_machine_check_ist_guard")
    );
    assert_eq!(
        address("__dw_ist_region_end") - address("__dw_ist_region_start"),
        15 * 4096
    );
    assert!(
        address("__dw_data_start") <= address("__dw_ist_region_start")
            && address("__dw_ist_region_end") <= address("__dw_data_end"),
        "linked IST arena escapes the writable data PT_LOAD bounds"
    );
    let thread_start = address("__dw_thread_kernel_stack_region_start");
    let thread_end = address("__dw_thread_kernel_stack_region_end");
    assert_eq!(thread_start & 0xfff, 0, "thread stack arena alignment");
    assert_eq!(thread_end - thread_start, 16 * (4096 + 262144));
    assert!(
        address("__dw_ist_region_end") <= thread_start && thread_end <= address("__dw_data_end"),
        "linked E3 thread stack arena escapes the writable data PT_LOAD bounds"
    );
    let privilege_guard = address("__dw_privilege_entry_stack_guard");
    let privilege_bottom = address("__dw_privilege_entry_stack_bottom");
    let privilege_top = address("__dw_privilege_entry_stack_top");
    assert_eq!(
        privilege_guard & 0xfff,
        0,
        "privilege-entry guard alignment"
    );
    assert_eq!(privilege_bottom - privilege_guard, 4096);
    assert_eq!(privilege_top - privilege_bottom, 16 * 1024);
    assert!(
        thread_end <= privilege_guard && privilege_top <= address("__dw_data_end"),
        "linked E4 privilege-entry stack escapes the writable data PT_LOAD bounds"
    );
    let terminal_guard = address("__dw_terminal_reaper_stack_guard");
    let terminal_bottom = address("__dw_terminal_reaper_stack_bottom");
    let terminal_top = address("__dw_terminal_reaper_stack_top");
    assert_eq!(terminal_guard & 0xfff, 0, "terminal reaper guard alignment");
    assert_eq!(terminal_bottom - terminal_guard, 4096);
    assert_eq!(terminal_top - terminal_bottom, 132 * 1024);
    assert!(
        privilege_top <= terminal_guard && terminal_top <= address("__dw_data_end"),
        "linked terminal reaper stack escapes the writable data PT_LOAD bounds"
    );
}

pub(crate) fn linked_thread_kernel_stack_payload_bytes(symbols: &str) -> usize {
    let addresses = symbols
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            Some((fields.next()?, address))
        })
        .collect::<BTreeMap<_, _>>();
    let address = |name: &str| {
        *addresses
            .get(name)
            .unwrap_or_else(|| panic!("target artifact omitted kernel-stack symbol {name}"))
    };
    let start = address("__dw_thread_kernel_stack_region_start");
    let end = address("__dw_thread_kernel_stack_region_end");
    const THREAD_STACKS: u64 = 16;
    const GUARD_BYTES: u64 = 4096;
    let per_thread = (end - start)
        .checked_div(THREAD_STACKS)
        .expect("thread stack count is nonzero");
    assert_eq!(
        end - start,
        per_thread * THREAD_STACKS,
        "thread kernel stack region has fractional per-thread geometry"
    );
    let payload = per_thread
        .checked_sub(GUARD_BYTES)
        .expect("thread kernel stack payload exceeds its per-thread region");
    usize::try_from(payload).expect("thread kernel stack payload fits usize")
}

pub(crate) fn linked_boot_stack_payload_bytes(symbols: &str) -> usize {
    let addresses = symbols
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            Some((fields.next()?, address))
        })
        .collect::<BTreeMap<_, _>>();
    let address = |name: &str| {
        *addresses
            .get(name)
            .unwrap_or_else(|| panic!("target artifact omitted boot-stack symbol {name}"))
    };
    usize::try_from(address("__dw_boot_stack_top") - address("__dw_boot_stack_bottom"))
        .expect("boot stack payload fits usize")
}

pub(crate) fn linked_terminal_reaper_stack_payload_bytes(symbols: &str) -> usize {
    let addresses = symbols
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            Some((fields.next()?, address))
        })
        .collect::<BTreeMap<_, _>>();
    let address = |name: &str| {
        *addresses
            .get(name)
            .unwrap_or_else(|| panic!("target artifact omitted terminal-stack symbol {name}"))
    };
    usize::try_from(
        address("__dw_terminal_reaper_stack_top") - address("__dw_terminal_reaper_stack_bottom"),
    )
    .expect("terminal reaper stack payload fits usize")
}
