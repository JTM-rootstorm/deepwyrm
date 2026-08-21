#![no_std]

#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/rights.rs"]
mod rights;
#[path = "../../src/handle/table.rs"]
mod table;

use table::HandleTransferToken;

fn clone_token(token: &HandleTransferToken) {
    let _ = <HandleTransferToken as Clone>::clone(token);
}
