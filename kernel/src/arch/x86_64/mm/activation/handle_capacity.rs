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
#[cfg(test)]
pub(super) const D6_INITIAL_HANDLES: usize = INITIAL_BOOTSTRAP_HANDLES + 1;
#[cfg(test)]
pub(super) const D6_RETAINED_TRIGGER_HANDLES: usize = 2;
#[cfg(test)]
pub(super) const D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES: usize = 1;
#[cfg(test)]
pub(super) const D6_HANDLE_PEAK: usize = D6_INITIAL_HANDLES
    + D6_RETAINED_TRIGGER_HANDLES
    + CHANNEL_CREATE_REDUCE_NET_HANDLES
    + PROCESS_ROOT_HANDLES
    + THREAD_HANDLES
    + D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES;

#[cfg(test)]
mod tests {
    use super::*;

    /// A bounded handle table: a claim past `capacity` fails without
    /// changing the occupancy, as the live HandleTable does.
    struct Table {
        live: usize,
        capacity: usize,
    }

    impl Table {
        fn claim(&mut self, count: usize) -> bool {
            match self.live.checked_add(count) {
                Some(next) if next <= self.capacity => {
                    self.live = next;
                    true
                }
                _ => false,
            }
        }

        fn move_out(&mut self, count: usize) -> bool {
            match self.live.checked_sub(count) {
                Some(next) => {
                    self.live = next;
                    true
                }
                None => false,
            }
        }

        /// The ordinary launch up to the INIT duplicates: inherited handles,
        /// the net ChannelCreate result, Process+root and Thread.
        fn launched(capacity: usize) -> Self {
            let mut table = Self { live: 0, capacity };
            for count in [
                INITIAL_BOOTSTRAP_HANDLES,
                CHANNEL_CREATE_REDUCE_NET_HANDLES,
                PROCESS_ROOT_HANDLES,
                THREAD_HANDLES,
            ] {
                assert!(table.claim(count), "launch overran {capacity} slots");
            }
            table
        }
    }

    #[test]
    fn the_bootstrap_peak_admits_both_init_duplicates_before_the_three_moves() {
        // One slot short of the peak, the second duplicate is refused and
        // nothing is overclaimed.
        let mut short = Table::launched(BOOTSTRAP_HANDLE_PEAK - 1);
        assert!(short.claim(1));
        assert!(!short.claim(1));
        assert_eq!(short.live, BOOTSTRAP_HANDLE_PEAK - 1);

        let mut table = Table::launched(BOOTSTRAP_HANDLE_PEAK);
        for _ in 0..INIT_DUPLICATE_HANDLES {
            assert!(table.claim(1));
        }
        assert_eq!(table.live, BOOTSTRAP_HANDLE_PEAK);
        assert!(!table.claim(1), "a full table must not overclaim");
        assert_eq!(table.live, BOOTSTRAP_HANDLE_PEAK);
        assert!(table.move_out(INIT_MOVED_HANDLES));
        assert_eq!(table.live, 7);
        assert_eq!(BOOTSTRAP_HANDLE_PEAK, 10);
    }

    #[test]
    fn the_d6_peak_admits_the_resource_domain_duplicate_and_the_returning_moves() {
        let launch = [
            D6_RETAINED_TRIGGER_HANDLES,
            CHANNEL_CREATE_REDUCE_NET_HANDLES,
            PROCESS_ROOT_HANDLES,
            THREAD_HANDLES,
        ];
        // Eleven slots admit the transient Thread but not the staged
        // resource-domain duplicate.
        let mut short = Table {
            live: D6_INITIAL_HANDLES,
            capacity: D6_HANDLE_PEAK - 1,
        };
        for count in launch {
            assert!(short.claim(count));
        }
        assert!(!short.claim(D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES));
        assert_eq!(short.live, D6_HANDLE_PEAK - 1);

        let mut table = Table {
            live: D6_INITIAL_HANDLES,
            capacity: D6_HANDLE_PEAK,
        };
        for count in launch {
            assert!(table.claim(count));
        }
        assert!(table.claim(D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES));
        assert_eq!(table.live, D6_HANDLE_PEAK);
        assert_eq!(D6_HANDLE_PEAK, 12);
        // The MOVE, then the parent root and Thread close back down.
        for _ in 0..3 {
            assert!(table.move_out(1));
        }
        assert_eq!(table.live, 9);
    }
}
