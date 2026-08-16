//! x86_64 task-state-segment layout and explicit stack configuration.
//!
//! The TSS is an architecture-private descriptor-table object. It does not
//! expose task or process policy and does not create a userspace ABI.

use core::mem::size_of;

/// x86_64 long-mode Task State Segment.
///
/// This exactly follows the architectural layout. It is packed because the
/// processor consumes this as a byte-defined hardware structure; ordinary
/// code must not take references to its multi-byte fields.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TaskStateSegment {
    reserved0: u32,
    privilege_stack_table: [u64; 3],
    reserved1: u64,
    interrupt_stack_table: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

impl TaskStateSegment {
    /// Creates a TSS with no privilege or interrupt stack configured.
    ///
    /// The I/O-map base is one byte past the TSS limit, which denies all
    /// lower-privilege I/O-port access until a later, explicit policy exists.
    pub const fn empty() -> Self {
        Self {
            reserved0: 0,
            privilege_stack_table: [0; 3],
            reserved1: 0,
            interrupt_stack_table: [0; 7],
            reserved2: 0,
            reserved3: 0,
            io_map_base: size_of::<Self>() as u16,
        }
    }

    /// Sets the kernel stack selected by an eventual lower-privilege entry.
    ///
    /// This lane does not allocate or map stacks. The caller must provide the
    /// exclusive, mapped top of a 16-byte-aligned kernel stack; `0` is
    /// rejected so an unconfigured TSS cannot be accidentally installed for
    /// privilege transitions.
    pub fn set_privilege_stack0(&mut self, stack_top: u64) -> Result<(), StackConfigurationError> {
        if stack_top == 0 || stack_top & 0xf != 0 {
            return Err(StackConfigurationError::InvalidStackTop);
        }
        self.privilege_stack_table[0] = stack_top;
        Ok(())
    }

    /// Configures one architecturally numbered interrupt stack table entry.
    ///
    /// x86_64 IST entries are numbered one through seven in IDT gates.
    pub fn set_interrupt_stack(
        &mut self,
        index: InterruptStackIndex,
        stack_top: u64,
    ) -> Result<(), StackConfigurationError> {
        if stack_top == 0 || stack_top & 0xf != 0 {
            return Err(StackConfigurationError::InvalidStackTop);
        }
        self.interrupt_stack_table[index.as_array_index()] = stack_top;
        Ok(())
    }

    /// Reads one installed IST top for activation-time carrier validation.
    #[must_use]
    #[cfg_attr(
        not(any(test, all(target_os = "none", target_arch = "x86_64"))),
        allow(
            dead_code,
            reason = "installed IST facts are consumed only by target activation"
        )
    )]
    #[allow(
        unsafe_code,
        reason = "the packed hardware TSS requires an unaligned value read without forming a reference"
    )]
    pub(crate) fn interrupt_stack(&self, index: InterruptStackIndex) -> u64 {
        let table = core::ptr::addr_of!(self.interrupt_stack_table).cast::<u64>();
        // SAFETY: `index` is one of the seven architectural slots and the
        // packed TSS remains live for the duration of this value-only read.
        unsafe { table.add(index.as_array_index()).read_unaligned() }
    }
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        Self::empty()
    }
}

/// A valid x86_64 interrupt-stack-table slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptStackIndex {
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
}

impl InterruptStackIndex {
    /// Encodes this stack slot for the low three bits of an IDT gate.
    #[must_use]
    pub(crate) const fn idt_bits(self) -> u8 {
        self.as_array_index() as u8 + 1
    }

    const fn as_array_index(self) -> usize {
        match self {
            Self::One => 0,
            Self::Two => 1,
            Self::Three => 2,
            Self::Four => 3,
            Self::Five => 4,
            Self::Six => 5,
            Self::Seven => 6,
        }
    }
}

/// Rejected hardware-stack configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackConfigurationError {
    InvalidStackTop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tss_matches_the_long_mode_hardware_layout() {
        assert_eq!(size_of::<TaskStateSegment>(), 104);
    }

    #[test]
    fn stack_tops_must_be_nonzero_and_suitably_aligned() {
        let mut tss = TaskStateSegment::empty();
        assert_eq!(
            tss.set_privilege_stack0(0),
            Err(StackConfigurationError::InvalidStackTop)
        );
        assert_eq!(
            tss.set_interrupt_stack(InterruptStackIndex::One, 0x1008),
            Err(StackConfigurationError::InvalidStackTop)
        );
        assert_eq!(tss.set_privilege_stack0(0x2000), Ok(()));
        assert_eq!(
            tss.set_interrupt_stack(InterruptStackIndex::Seven, 0x3000),
            Ok(())
        );
        assert_eq!(tss.interrupt_stack(InterruptStackIndex::One), 0);
        assert_eq!(tss.interrupt_stack(InterruptStackIndex::Seven), 0x3000);
        assert_eq!(InterruptStackIndex::One.idt_bits(), 1);
        assert_eq!(InterruptStackIndex::Seven.idt_bits(), 7);
    }
}
