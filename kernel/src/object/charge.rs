//! Quota charge tags carried by registry slots (F4 DW1-F4-M1). The policy
//! that reads them is `crate::task::quota`.

use deepwyrm_abi::{
    DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP, DW_OBJECT_TYPE_THREAD, DW_OBJECT_TYPE_TIMER,
    DwObjectType,
};

use super::ObjectId;

/// The most limited TaskGroups a process may have above it. Creation by a
/// process with more is refused, so a tag never drops one.
pub(crate) const MAX_LIMITED_ANCESTORS: usize = 4;

/// The object class an object type is limited under, if any. The class
/// values are the ABI's `DW_TASK_GROUP_LIMIT_*` constants.
pub(crate) const fn object_class(object_type: DwObjectType) -> Option<usize> {
    match object_type {
        DW_OBJECT_TYPE_CHANNEL => Some(0),
        DW_OBJECT_TYPE_EVENT => Some(1),
        DW_OBJECT_TYPE_TIMER => Some(2),
        DW_OBJECT_TYPE_MEMORY_OBJECT => Some(3),
        DW_OBJECT_TYPE_THREAD => Some(4),
        DW_OBJECT_TYPE_PROCESS => Some(5),
        DW_OBJECT_TYPE_TASK_GROUP => Some(6),
        _ => None,
    }
}

/// The limited TaskGroups above the creating process, nearest first.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChargeTag {
    groups: [Option<ObjectId>; MAX_LIMITED_ANCESTORS],
}

impl ChargeTag {
    pub(crate) const EMPTY: Self = Self {
        groups: [None; MAX_LIMITED_ANCESTORS],
    };

    /// Appends a limited ancestor. `false` when the tag is full.
    pub(crate) fn push(&mut self, group: ObjectId) -> bool {
        match self.groups.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(group);
                true
            }
            None => false,
        }
    }

    pub(crate) fn names(&self, group: ObjectId) -> bool {
        self.groups.contains(&Some(group))
    }

    pub(crate) fn groups(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.groups.iter().flatten().copied()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.groups[0].is_none()
    }
}
