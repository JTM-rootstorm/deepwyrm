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
            .unwrap_or_else(|| panic!("production artifact omitted IST symbol {name}"))
    };
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
    assert_eq!(thread_end - thread_start, 16 * (4096 + 65536));
    assert!(
        address("__dw_ist_region_end") <= thread_start && thread_end <= address("__dw_data_end"),
        "linked E3 thread stack arena escapes the writable data PT_LOAD bounds"
    );
}
