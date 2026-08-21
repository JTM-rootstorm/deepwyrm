#![no_std]

include!("f11_full_kernel_modules.rs");

use ipc::ChannelSendReservation;

fn clone_reservation(reservation: &ChannelSendReservation) {
    let _ = <ChannelSendReservation as Clone>::clone(reservation);
}
