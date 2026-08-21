#![no_std]

#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/rights.rs"]
mod rights;
#[path = "../../src/handle/table.rs"]
mod table;

use table::HandleTransferBatch;

fn clone_batch(batch: &HandleTransferBatch) {
    let _ = <HandleTransferBatch as Clone>::clone(batch);
}
