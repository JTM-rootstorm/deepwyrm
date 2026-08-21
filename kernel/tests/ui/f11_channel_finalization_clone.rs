#![no_std]

include!("f11_full_kernel_modules.rs");

use ipc::ChannelFinalization;

fn clone_finalization(finalization: &ChannelFinalization<1, 1>) {
    let _ = <ChannelFinalization<1, 1> as Clone>::clone(finalization);
}
