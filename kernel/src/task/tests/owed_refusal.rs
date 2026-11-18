//! DW2 §13.12 part b: the quota half of the rule that decides whether a
//! refusal is owed, `TaskAuthority::quota_refusal_owed`, against the same
//! limits `admit_quota` reads.

use super::*;
use crate::task::quota::{ChargeTag, MEMORY_PAGES_CLASS, object_class};
use deepwyrm_abi::{
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_TASK_GROUP_LIMIT_MEMORY_OBJECT,
    DW_TASK_GROUP_LIMIT_MEMORY_PAGES,
};

/// A root group with a child, both limited in `class` (the root to
/// `root_limit`, the child to `child_limit`), and the tag a process in the
/// child is charged with: the child, then the root.
fn two_limited_groups(
    class: u32,
    root_limit: u32,
    child_limit: u32,
) -> (Tasks, ObjectId, ObjectId, ChargeTag) {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (child, _) = tasks
        .create_child_group(&mut registry, &root_owner)
        .unwrap();
    tasks.lower_group_limit(root, class, root_limit).unwrap();
    tasks.lower_group_limit(child, class, child_limit).unwrap();
    let tag = tasks.group_charge_tag(child.object_id()).unwrap();
    assert!(tag.names(root.object_id()) && tag.names(child.object_id()));
    (tasks, root.object_id(), child.object_id(), tag)
}

/// Asks the rule with per-group figures: `(usage, finalizing)` for the root
/// and for the child.
fn owed(
    tasks: &Tasks,
    (root, child): (ObjectId, ObjectId),
    tag: &ChargeTag,
    class: usize,
    needed: usize,
    figures: [(usize, usize); 2],
) -> bool {
    let figure = |group: ObjectId, part: fn((usize, usize)) -> usize| {
        if group == root {
            part(figures[0])
        } else if group == child {
            part(figures[1])
        } else {
            panic!("a group outside the tag was asked")
        }
    };
    tasks.quota_refusal_owed(
        tag,
        class,
        needed,
        |group| figure(group, |(usage, _)| usage),
        |group| figure(group, |(_, finalizing)| finalizing),
    )
}

/// Whether `admit_quota` refuses with the same usage.
fn refuses(
    tasks: &Tasks,
    (root, child): (ObjectId, ObjectId),
    tag: &ChargeTag,
    class: usize,
    needed: usize,
    usage: [usize; 2],
) -> bool {
    tasks
        .admit_quota(tag, class, needed, |group| {
            assert!(group == root || group == child, "a group outside the tag");
            if group == root { usage[0] } else { usage[1] }
        })
        .is_err()
}

#[test]
fn the_page_class_refusal_is_owed_only_when_finalizing_pages_would_admit_it() {
    let (tasks, root, child, tag) =
        two_limited_groups(DW_TASK_GROUP_LIMIT_MEMORY_PAGES, 1_000, 100);
    let groups = (root, child);
    let class = MEMORY_PAGES_CLASS;
    // Nothing refuses: not owed, whatever is finalizing.
    assert!(!refuses(&tasks, groups, &tag, class, 10, [50, 50]));
    assert!(!owed(&tasks, groups, &tag, class, 10, [(50, 50), (50, 50)]));
    assert!(!owed(&tasks, groups, &tag, class, 10, [(50, 0), (90, 0)]));
    // The child refuses (95 + 10 > 100) and its finalizing 5 would admit:
    // 95 - 5 + 10 = 100.
    assert!(refuses(&tasks, groups, &tag, class, 10, [95, 95]));
    assert!(owed(&tasks, groups, &tag, class, 10, [(95, 0), (95, 5)]));
    // With 4 finalizing it would still refuse: the refusal is real.
    assert!(!owed(&tasks, groups, &tag, class, 10, [(95, 0), (95, 4)]));
    // Nothing finalizing: real.
    assert!(!owed(&tasks, groups, &tag, class, 10, [(95, 0), (95, 0)]));
    // A non-refusing group's figures do not matter: the root admits, with
    // nothing of it finalizing.
    assert!(owed(&tasks, groups, &tag, class, 10, [(990, 0), (95, 95)]));
}

#[test]
fn two_refusing_groups_are_owed_only_when_each_is() {
    let (tasks, root, child, tag) = two_limited_groups(DW_TASK_GROUP_LIMIT_MEMORY_PAGES, 200, 100);
    let groups = (root, child);
    let class = MEMORY_PAGES_CLASS;
    assert!(refuses(&tasks, groups, &tag, class, 10, [195, 95]));
    // Both refuse and both would admit with their finalizing pages gone.
    assert!(owed(&tasks, groups, &tag, class, 10, [(195, 5), (95, 5)]));
    // The child is owed and the root is not: not owed.
    assert!(!owed(&tasks, groups, &tag, class, 10, [(195, 4), (95, 95)]));
    // The root is owed and the child is not: not owed.
    assert!(!owed(
        &tasks,
        groups,
        &tag,
        class,
        10,
        [(195, 195), (95, 0)]
    ));
}

#[test]
fn an_object_class_refusal_asks_that_class_s_figures() {
    let class = object_class(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    assert_eq!(class, DW_TASK_GROUP_LIMIT_MEMORY_OBJECT as usize);
    let (tasks, root, child, tag) =
        two_limited_groups(DW_TASK_GROUP_LIMIT_MEMORY_OBJECT, 1_000, 64);
    let groups = (root, child);
    // 64 of 64 counted, none live (§13.10's measurement): owed.
    assert!(refuses(&tasks, groups, &tag, class, 1, [64, 64]));
    assert!(owed(&tasks, groups, &tag, class, 1, [(64, 64), (64, 64)]));
    // One of them finalizing is enough room for one more.
    assert!(owed(&tasks, groups, &tag, class, 1, [(64, 0), (64, 1)]));
    // All 64 live: a group truly at its limit is refused.
    assert!(!owed(&tasks, groups, &tag, class, 1, [(64, 0), (64, 0)]));
    // 63 of 64: nothing refuses.
    assert!(!owed(&tasks, groups, &tag, class, 1, [(63, 0), (63, 0)]));
    // The page class is unlimited here: it never refuses.
    assert!(!owed(
        &tasks,
        groups,
        &tag,
        MEMORY_PAGES_CLASS,
        usize::MAX,
        [(usize::MAX, 0), (usize::MAX, 0)]
    ));
}
