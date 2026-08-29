//! DW1-D2 typed device-resource authority.

mod resource;

pub(crate) use resource::DeviceResourceBinding;
#[allow(
    unused_imports,
    reason = "D2 exports the complete typed DeviceResource seam before D5 production publication"
)]
pub(crate) use resource::{
    DeviceResourceAuthority, DeviceResourceCleanup, DeviceResourceCreateError,
    DeviceResourceDescriptor, DeviceResourceError, DeviceResourceFinalization,
    DeviceResourceFinalizer, DeviceResourceInfoProvider, DeviceResourceKey,
    complete_device_resource_finalization, pio_read, pio_write,
};

#[cfg(test)]
mod tests;
