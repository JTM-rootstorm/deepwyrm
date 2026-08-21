#![no_std]

#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/rights.rs"]
mod rights;
#[path = "../../src/handle/table.rs"]
mod table;

use table::PreparedHandleMoveRollback;

fn clone_rollback(rollback: &PreparedHandleMoveRollback) {
    let _ = <PreparedHandleMoveRollback as Clone>::clone(rollback);
}
