#![no_std]

#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/rights.rs"]
mod rights;
#[path = "../../src/handle/table.rs"]
mod table;

use table::PreparedHandleMove;

fn clone_move(prepared: &PreparedHandleMove) {
    let _ = <PreparedHandleMove as Clone>::clone(prepared);
}
