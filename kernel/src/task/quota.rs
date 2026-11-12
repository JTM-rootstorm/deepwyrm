//! TaskGroup object and wait limits (`task_group_limit`, F4 DW1-F4-M1).
//!
//! A TaskGroup may carry a limit per class. A limit bounds what processes
//! anywhere in the group's subtree create after it is set: live objects of
//! the class, or concurrently registered wait items. Limits only fall.
//!
//! Usage is never counted up and down. Each object created by a process
//! records, in its registry slot, the limited TaskGroups above that process
//! (its [`ChargeTag`]). A group's usage is the number of live slots whose tag
//! names it, so a finalized object stops counting the moment its slot is
//! released, with no separate release path to get wrong. Wait usage is
//! derived the same way, from the waiting threads of the live wait entries.
//! A tag keeps naming a TaskGroup after that group dies; its key carries a
//! generation and is never reissued, so the tag can neither count against
//! another group nor escape its live ancestors, which it also names.

use deepwyrm_abi::{
    DW_TASK_GROUP_LIMIT_CLASS_COUNT, DW_TASK_GROUP_LIMIT_MEMORY_PAGES,
    DW_TASK_GROUP_LIMIT_UNLIMITED, DW_TASK_GROUP_LIMIT_WAIT,
};

pub(crate) use crate::object::charge::{ChargeTag, object_class};

pub(crate) const LIMIT_CLASSES: usize = DW_TASK_GROUP_LIMIT_CLASS_COUNT as usize;
pub(crate) const UNLIMITED: u32 = DW_TASK_GROUP_LIMIT_UNLIMITED;
pub(crate) const WAIT_CLASS: usize = DW_TASK_GROUP_LIMIT_WAIT as usize;
/// The page-weighted class (D6): usage is the sum of the RAM-backed
/// MemoryObject pages charged to a group, not a count of objects.
pub(crate) const MEMORY_PAGES_CLASS: usize = DW_TASK_GROUP_LIMIT_MEMORY_PAGES as usize;

const _: () = {
    assert!(WAIT_CLASS == 7);
    assert!(MEMORY_PAGES_CLASS == 8);
    assert!(LIMIT_CLASSES == 9);
};

/// Why a quota admission refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuotaError {
    /// A limited ancestor is at its limit.
    Exceeded,
    /// The creator has more than `MAX_LIMITED_ANCESTORS` limited ancestors.
    TooDeep,
    /// The creating process or thread is not live.
    Task,
}

/// Why `task_group_limit` refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LimitError {
    Task(super::TaskError),
    /// An unknown class, or a limit above the current one.
    InvalidArgument,
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT, DW_OBJECT_TYPE_MEMORY_OBJECT,
        DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP, DW_OBJECT_TYPE_THREAD,
        DW_OBJECT_TYPE_TIMER, DW_TASK_GROUP_LIMIT_CHANNEL, DW_TASK_GROUP_LIMIT_EVENT,
        DW_TASK_GROUP_LIMIT_MEMORY_OBJECT, DW_TASK_GROUP_LIMIT_PROCESS,
        DW_TASK_GROUP_LIMIT_TASK_GROUP, DW_TASK_GROUP_LIMIT_THREAD, DW_TASK_GROUP_LIMIT_TIMER,
    };

    #[test]
    fn object_classes_are_the_abi_constants() {
        for (object_type, class) in [
            (DW_OBJECT_TYPE_CHANNEL, DW_TASK_GROUP_LIMIT_CHANNEL),
            (DW_OBJECT_TYPE_EVENT, DW_TASK_GROUP_LIMIT_EVENT),
            (DW_OBJECT_TYPE_TIMER, DW_TASK_GROUP_LIMIT_TIMER),
            (
                DW_OBJECT_TYPE_MEMORY_OBJECT,
                DW_TASK_GROUP_LIMIT_MEMORY_OBJECT,
            ),
            (DW_OBJECT_TYPE_THREAD, DW_TASK_GROUP_LIMIT_THREAD),
            (DW_OBJECT_TYPE_PROCESS, DW_TASK_GROUP_LIMIT_PROCESS),
            (DW_OBJECT_TYPE_TASK_GROUP, DW_TASK_GROUP_LIMIT_TASK_GROUP),
        ] {
            assert_eq!(object_class(object_type), Some(class as usize));
        }
    }

    #[test]
    fn the_page_and_wait_classes_are_no_object_type_s_class() {
        for object_type in 0..64 {
            let class = object_class(deepwyrm_abi::DwObjectType(object_type));
            assert_ne!(class, Some(MEMORY_PAGES_CLASS));
            assert_ne!(class, Some(WAIT_CLASS));
        }
    }
}
