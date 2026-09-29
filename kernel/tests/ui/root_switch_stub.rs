// Minimal `super` context for the compile-fail fixtures that build
// `mm/activation/root_switch.rs` as a standalone crate (S2K-2).
//
// `root_switch.rs` names its paging inputs through `super::`, the
// `activation` module, whose real types need the whole paging stack. These
// stand-ins carry the same names and `execute` signatures and nothing else:
// the fixtures never run, and none of them derives `Clone` or `Copy`, exactly
// like the real move-only tokens. Each fixture's code sits at the crate root,
// a sibling of `root_switch`, which is where `primordial.rs` sits.

#[path = "../../src/cpu.rs"]
mod cpu;

pub(crate) mod task {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ProcessKey;
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ThreadKey;
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct KernelStackId;
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ThreadContextId;
}

pub(crate) mod memory {
    pub(crate) mod address_region {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) struct AddressRegionObjectKey;
    }
}

pub(crate) trait RootSwitchTarget {}

pub(crate) struct ActiveRootSelection;
pub(crate) struct ActiveKernelExecutionRoot;
pub(crate) struct RootBindingError;
pub(crate) struct RootSelectionFailure;
pub(crate) struct KernelRootSelectionFailure;
pub(crate) struct PreparedProcessRootSwitch;
pub(crate) struct ExecutedProcessRootSwitch;
pub(crate) struct PreparedKernelToProcessRootSwitch;
pub(crate) struct ExecutedKernelToProcessRootSwitch;
pub(crate) struct PreparedKernelExecutionRootSwitch;
pub(crate) struct ExecutedKernelExecutionRootSwitch;
pub(crate) struct PreparedKernelRootEntry;
pub(crate) struct ExecutedKernelRootEntry;

impl PreparedProcessRootSwitch {
    pub(crate) fn execute<T: RootSwitchTarget>(
        self,
        _target: &mut T,
    ) -> Result<ExecutedProcessRootSwitch, RootSelectionFailure> {
        Ok(ExecutedProcessRootSwitch)
    }
}

impl PreparedKernelToProcessRootSwitch {
    pub(crate) fn execute<T: RootSwitchTarget>(
        self,
        _target: &mut T,
    ) -> Result<ExecutedKernelToProcessRootSwitch, KernelRootSelectionFailure> {
        Ok(ExecutedKernelToProcessRootSwitch)
    }
}

impl PreparedKernelExecutionRootSwitch {
    pub(crate) fn execute<T: RootSwitchTarget>(
        self,
        _target: &mut T,
    ) -> Result<ExecutedKernelExecutionRootSwitch, (RootBindingError, ActiveRootSelection)> {
        Ok(ExecutedKernelExecutionRootSwitch)
    }
}

impl PreparedKernelRootEntry {
    pub(crate) fn execute<T: RootSwitchTarget>(
        self,
        _target: &mut T,
    ) -> Result<ExecutedKernelRootEntry, (RootBindingError, PreparedKernelRootEntry)> {
        Ok(ExecutedKernelRootEntry)
    }
}

#[path = "../../src/arch/x86_64/mm/activation/root_switch.rs"]
mod root_switch;
