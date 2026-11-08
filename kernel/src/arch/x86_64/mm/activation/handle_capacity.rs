//! The primordial Process's live handle-table geometry: the per-step handle
//! deltas of the bootstrap launch and the peaks they sum to.
//!
//! Split out of the target-only `primordial.rs` (S3) so that the host `test`
//! build compiles the constants `primordial.rs` sizes its handle table from,
//! and their capacity model runs against them.

// Exact live bootstrap peak per Process: four inherited handles, one net
// ChannelCreate/rights-reduction result, Process+root, and Thread fill eight
// slots; the two reduced-right duplicates needed before the three-handle INIT
// move raise the pre-transfer peak to ten.
pub(super) const INITIAL_BOOTSTRAP_HANDLES: usize = 4;
pub(super) const CHANNEL_CREATE_REDUCE_NET_HANDLES: usize = 1;
pub(super) const PROCESS_ROOT_HANDLES: usize = 2;
pub(super) const THREAD_HANDLES: usize = 1;
pub(super) const INIT_DUPLICATE_HANDLES: usize = 2;
pub(super) const INIT_MOVED_HANDLES: usize = 3;
pub(super) const BOOTSTRAP_HANDLE_PEAK: usize = INITIAL_BOOTSTRAP_HANDLES
    + CHANNEL_CREATE_REDUCE_NET_HANDLES
    + PROCESS_ROOT_HANDLES
    + THREAD_HANDLES
    + INIT_DUPLICATE_HANDLES;
// Selector 30 receives the ordinary four bootstrap capabilities plus the
// boot-resource domain.  After the first owner exits, bootstrap retains the
// trigger's Process and launch Channel while the replacement owner loader
// holds its net Channel, Process+root, Thread, and resource-domain staging
// duplicate.  That exact replacement-launch peak is twelve handles.
#[cfg(any(test, deepwyrm_dw1d_evidence))]
pub(super) const D6_INITIAL_HANDLES: usize = INITIAL_BOOTSTRAP_HANDLES + 1;
#[cfg(any(test, deepwyrm_dw1d_evidence))]
pub(super) const D6_RETAINED_TRIGGER_HANDLES: usize = 2;
#[cfg(any(test, deepwyrm_dw1d_evidence))]
pub(super) const D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES: usize = 1;
#[cfg(any(test, deepwyrm_dw1d_evidence))]
pub(super) const D6_HANDLE_PEAK: usize = D6_INITIAL_HANDLES
    + D6_RETAINED_TRIGGER_HANDLES
    + CHANNEL_CREATE_REDUCE_NET_HANDLES
    + PROCESS_ROOT_HANDLES
    + THREAD_HANDLES
    + D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES;
