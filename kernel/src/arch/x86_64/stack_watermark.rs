//! Measured kernel-stack high-water marks (DW2 M5 §10.2 item 2, the
//! measured half of the stack check).
//!
//! `xtask kernel-check` bounds every direct call chain statically, but calls
//! through trait objects and function pointers in writable memory are not
//! bounded there. This module measures what actually ran: every kernel stack
//! payload is painted with [`PAINT`] once, before anything can run on it, and
//! at power-off each is scanned from its low end for the first word that is no
//! longer paint. Nothing repaints a stack, so the mark is the deepest any
//! Thread or CPU reached on that stack during the boot. The production boot
//! logs one `[stack]` record per class with the deepest mark and the usable
//! size; Wyrmroot's `dev-boot --check` bounds each.
//!
//! The boot stack and the BSP's pre-migration carriers are not covered: they
//! are in use before painting can happen, and the runtime moves off them.

/// The paint word. Any value works; this one is unlikely as a saved
/// register, return address or local.
pub(crate) const PAINT: u64 = 0x57ac_c0de_dead_57ac;

/// Fills a stack payload with paint.
pub(crate) fn paint(words: &mut [u64]) {
    words.fill(PAINT);
}

/// Bytes of a painted payload that have been written, counting from its high
/// end down to the lowest word that is no longer paint. Stacks grow down, so
/// the untouched words are the run of paint at the low end.
pub(crate) fn high_water_bytes(len_words: usize, word_at: impl Fn(usize) -> u64) -> usize {
    let untouched = (0..len_words)
        .position(|index| word_at(index) != PAINT)
        .unwrap_or(len_words);
    (len_words - untouched) * 8
}

/// One stack class's deepest mark across its stacks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ClassMark {
    pub(crate) deepest: usize,
    pub(crate) usable: usize,
}

impl ClassMark {
    pub(crate) fn record(&mut self, used: usize, usable: usize) {
        self.deepest = self.deepest.max(used);
        self.usable = if self.usable == 0 {
            usable
        } else {
            self.usable.min(usable)
        };
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live {
    use super::{ClassMark, high_water_bytes, paint};
    use crate::memory::kernel_stack::KernelStackBounds;

    const CLASSES: [&str; 5] = ["thread", "privilege-entry", "reaper", "ist", "ap-bootstrap"];

    /// Every painted payload with its class index into [`CLASSES`].
    fn for_each_stack(mut visit: impl FnMut(usize, KernelStackBounds)) {
        if let Ok(threads) = crate::arch::x86_64::linked_thread_kernel_stack_layout() {
            for stack in threads {
                visit(0, stack);
            }
        }
        if let Ok(slots) = crate::arch::x86_64::linked_runtime_cpu_stack_layout() {
            for slot in slots {
                visit(1, slot.privilege_entry);
                visit(2, slot.terminal_reaper);
                for stack in slot.interrupt_stacks {
                    visit(3, stack);
                }
                visit(4, slot.ap_bootstrap);
            }
        }
    }

    fn words(stack: KernelStackBounds) -> usize {
        (stack.byte_len() / 8) as usize
    }

    /// Paints every covered stack.
    ///
    /// # Safety
    ///
    /// Called once, by the BSP at the start of `kernel_main`, while it runs on
    /// the boot stack: no covered stack is in use, and the loader's transition
    /// mapping covers the whole writable image, so every payload is mapped.
    #[allow(
        unsafe_code,
        reason = "writes the linker-reserved stack payloads before any execution uses them"
    )]
    pub(crate) unsafe fn paint_all() {
        for_each_stack(|_, stack| {
            // SAFETY: the caller's contract; the payload excludes the guard
            // page and is 8-byte aligned and sized.
            let payload =
                unsafe { core::slice::from_raw_parts_mut(stack.bottom as *mut u64, words(stack)) };
            paint(payload);
        });
    }

    /// Scans every covered stack and logs each class's deepest mark.
    #[allow(
        unsafe_code,
        reason = "reads stack payloads, some live on other CPUs, as plain words"
    )]
    pub(crate) fn report() {
        let mut marks = [ClassMark::default(); CLASSES.len()];
        for_each_stack(|class, stack| {
            let base = stack.bottom as *const u64;
            let used = high_water_bytes(words(stack), |index| {
                // SAFETY: inside the mapped payload. A live stack may change
                // under the read; volatile keeps each read a real load, and a
                // word is read once, so the mark is at worst slightly stale.
                unsafe { core::ptr::read_volatile(base.add(index)) }
            });
            marks[class].record(used, stack.byte_len() as usize);
        });
        for (name, mark) in CLASSES.iter().zip(marks) {
            let mut line = Line::new();
            let _ = core::fmt::Write::write_fmt(
                &mut line,
                format_args!(
                    "class={name} deepest={} usable={}",
                    mark.deepest, mark.usable
                ),
            );
            if let Ok(message) = core::str::from_utf8(line.text()) {
                let _ = crate::debug::emit_early_record(
                    crate::debug::DiagnosticLevel::Info,
                    "stack",
                    message,
                );
            }
        }
    }

    struct Line {
        bytes: [u8; 80],
        len: usize,
    }

    impl Line {
        const fn new() -> Self {
            Self {
                bytes: [0; 80],
                len: 0,
            }
        }

        fn text(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    impl core::fmt::Write for Line {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.len + text.len();
            let slot = self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?;
            slot.copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use live::{paint_all, report};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untouched_stack_reports_zero_and_a_full_one_its_size() {
        let mut stack = [0_u64; 64];
        paint(&mut stack);
        assert_eq!(high_water_bytes(stack.len(), |index| stack[index]), 0);
        stack[0] = 1;
        assert_eq!(high_water_bytes(stack.len(), |index| stack[index]), 512);
    }

    #[test]
    fn the_mark_is_the_lowest_written_word_even_past_untouched_gaps() {
        let mut stack = [0_u64; 64];
        paint(&mut stack);
        // Writes near the top, then one deep write with paint between: the
        // deepest write decides, as a frame that reserved but skipped words.
        stack[63] = 7;
        stack[62] = 7;
        stack[40] = 7;
        assert_eq!(high_water_bytes(stack.len(), |index| stack[index]), 24 * 8);
        // A word that happens to hold the paint value counts as untouched.
        stack[40] = PAINT;
        assert_eq!(high_water_bytes(stack.len(), |index| stack[index]), 2 * 8);
    }

    #[test]
    fn a_class_keeps_its_deepest_mark_and_smallest_usable_size() {
        let mut mark = ClassMark::default();
        mark.record(100, 4096);
        mark.record(300, 4096);
        mark.record(200, 8192);
        assert_eq!(
            mark,
            ClassMark {
                deepest: 300,
                usable: 4096
            }
        );
    }
}
