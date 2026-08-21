#![no_std]

#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/rights.rs"]
mod rights;
#[path = "../../src/handle/table.rs"]
mod table;

use table::HandleTransferReservation;

fn clone_reservation(reservation: &HandleTransferReservation) {
    let _ = <HandleTransferReservation as Clone>::clone(reservation);
}
