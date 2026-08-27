use super::*;

pub(crate) fn validate_primordial_boot_stack_margin(
    selector: &str,
    sizes: &[StackSize],
    boot_stack_bytes: usize,
) {
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    // The assembly entry calls kernel_main, kernel_main calls run_primordial,
    // and run_primordial calls primordial::enter. Stack-size records exclude
    // those three retained return words.
    const RETAINED_RETURN_ADDRESS_BYTES: usize = 3 * size_of::<u64>();

    let kernel_main = one_stack_size(sizes, "kernel_main", |symbol| {
        symbol == "deepwyrm_kernel::kernel_main"
    });
    let run_primordial = one_stack_size(sizes, "run_primordial", |symbol| {
        symbol.ends_with(">>::run_primordial")
    });
    let primordial_enter = one_stack_size(sizes, "primordial enter", |symbol| {
        symbol.contains("::mm::transition::activation::primordial::enter::<")
            && !symbol.contains("::{closure")
    });
    let measured_chain = kernel_main
        .checked_add(run_primordial)
        .and_then(|bytes| bytes.checked_add(primordial_enter))
        .expect("primordial retained stack chain fits usize");
    let required = measured_chain
        .checked_add(RETAINED_RETURN_ADDRESS_BYTES)
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .and_then(|bytes| bytes.checked_add(REQUIRED_SPARE_BYTES))
        .expect("primordial boot-stack requirement fits usize");

    assert!(
        required <= boot_stack_bytes,
        "{selector} retained primordial stack chain does not fit the linked boot stack: \
         kernel_main={kernel_main} run_primordial={run_primordial} \
         primordial_enter={primordial_enter} measured_chain={measured_chain} \
         return_addresses={RETAINED_RETURN_ADDRESS_BYTES} \
         architectural_headroom={ARCHITECTURAL_HEADROOM_BYTES} \
         required_spare={REQUIRED_SPARE_BYTES} required={required} \
         linked_boot_stack={boot_stack_bytes}"
    );
    eprintln!(
        "{selector} primordial stack kernel-main={kernel_main} \
         run-primordial={run_primordial} enter={primordial_enter} \
         measured={measured_chain} returns={RETAINED_RETURN_ADDRESS_BYTES} \
         headroom={ARCHITECTURAL_HEADROOM_BYTES} required-spare={REQUIRED_SPARE_BYTES} \
         linked-boot-stack={boot_stack_bytes} remaining={}",
        boot_stack_bytes - required
    );
}
