//! DW1-D typed device-resource and synthetic Interrupt authorities.

mod interrupt;
mod resource;

pub(crate) use interrupt::InterruptPayloadBinding;
#[allow(
    unused_imports,
    reason = "D3 exports the complete typed Interrupt seam before D5 production publication"
)]
pub(crate) use interrupt::{
    InterruptAckTransaction, InterruptAuthority, InterruptCleanup, InterruptCreateError,
    InterruptError, InterruptFinalization, InterruptFinalizer, InterruptInfoProvider, InterruptKey,
    InterruptPlatform, InterruptPlatformError, InterruptPlatformModel, InterruptWaitFailure,
    InterruptWaitOutcome, InterruptWaitSource, complete_interrupt_finalization, interrupt_ack,
    interrupt_create, prepare_interrupt_ack,
};

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
mod interrupt_tests;
#[cfg(test)]
mod tests;
