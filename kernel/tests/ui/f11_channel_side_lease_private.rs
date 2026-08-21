#![no_std]

include!("f11_full_kernel_modules.rs");

use ipc::ChannelSideLease;

fn name_pair_lease(_: Option<ChannelSideLease>) {}
