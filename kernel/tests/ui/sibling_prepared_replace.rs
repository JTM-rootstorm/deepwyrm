#![allow(dead_code)]

#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::object::PreparedReplace;

    fn commit_without_publication(prepared: PreparedReplace<'_, 1, 1, 1>) {
        let _ = prepared.tickets();
        prepared.commit();
    }
}
