//! DW1-D typed device-resource and synthetic Interrupt authorities.

mod interrupt;
#[cfg(any(test, deepwyrm_dw1e_platform))]
mod q35_interrupt;
mod resource;

pub(crate) use interrupt::InterruptPayloadBinding;
#[allow(
    unused_imports,
    reason = "D3 exports the complete typed Interrupt seam before D5 production publication"
)]
pub(crate) use interrupt::{
    InterruptAckOutcome, InterruptAckTransaction, InterruptAuthority, InterruptCleanup,
    InterruptCreateError, InterruptDeliveryDisposition, InterruptError, InterruptFinalization,
    InterruptFinalizer, InterruptInfoProvider, InterruptKey, InterruptPlatform,
    InterruptPlatformAck, InterruptPlatformError, InterruptPlatformModel, InterruptWaitFailure,
    InterruptWaitOutcome, InterruptWaitSource, complete_interrupt_finalization, interrupt_ack,
    interrupt_create, prepare_interrupt_ack,
};

#[cfg(deepwyrm_dw1e_platform)]
pub(crate) use q35_interrupt::{Q35DeliverySnapshot, Q35InterruptPlatform};

#[cfg(any(test, deepwyrm_dw1d_evidence))]
#[allow(
    unused_imports,
    reason = "selector-30 collector and target runtime consume the private binding identity"
)]
pub(crate) use interrupt::InterruptBinding;

pub(crate) use resource::DeviceResourceBinding;
#[allow(
    unused_imports,
    reason = "D2 exports the complete typed DeviceResource seam before D5 production publication"
)]
pub(crate) use resource::{
    DeviceResourceAuthority, DeviceResourceCleanup, DeviceResourceCreateError,
    DeviceResourceDescriptor, DeviceResourceError, DeviceResourceFinalization,
    DeviceResourceFinalizer, DeviceResourceGrantLease, DeviceResourceInfoProvider,
    DeviceResourceKey, cancel_unpublished_device_resource_claim,
    complete_device_resource_finalization, complete_device_resource_finalization_with_grants,
    pio_read, pio_write,
};

#[cfg(test)]
mod interrupt_tests;
#[cfg(test)]
mod tests;
