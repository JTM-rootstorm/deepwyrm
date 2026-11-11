//! PCI configuration mechanism #1 (ports 0xCF8/0xCFC), kernel-only.
//!
//! `DW2_PCI_DEVICE_DMA_CONTRACT.md` §3: userspace never receives these ports.
//! Every access is one address write and one data access under a single
//! IRQ-safe lock, so concurrent CPUs cannot interleave an address with
//! another CPU's data cycle.

use crate::arch::x86_64::io_port::ScalarPortIo;
use crate::device::pci::{ConfigSpace, PciAddress};
use crate::sync::IrqSpinMutex;

const CONFIG_ADDRESS: u16 = 0xcf8;
const CONFIG_DATA: u16 = 0xcfc;
const ENABLE: u32 = 1 << 31;

/// The configuration-address dword for one aligned register.
pub(crate) const fn config_address(address: PciAddress, offset: u8) -> u32 {
    ENABLE
        | (address.bus() as u32) << 16
        | (address.device() as u32) << 11
        | (address.function() as u32) << 8
        | (offset & 0xfc) as u32
}

/// Mechanism #1 over any scalar port backend.
pub(crate) struct Mechanism1<'a, P: ScalarPortIo> {
    ports: &'a mut P,
}

impl<'a, P: ScalarPortIo> Mechanism1<'a, P> {
    #[cfg_attr(
        test,
        allow(dead_code, reason = "host tests drive the address encoding only")
    )]
    pub(crate) fn new(ports: &'a mut P) -> Self {
        Self { ports }
    }
}

impl<P: ScalarPortIo> ConfigSpace for Mechanism1<'_, P> {
    fn read32(&mut self, address: PciAddress, offset: u8) -> u32 {
        let _guard = CONFIG_LOCK.lock();
        self.ports
            .write_u32(CONFIG_ADDRESS, config_address(address, offset));
        self.ports.read_u32(CONFIG_DATA)
    }

    fn write32(&mut self, address: PciAddress, offset: u8, value: u32) {
        let _guard = CONFIG_LOCK.lock();
        self.ports
            .write_u32(CONFIG_ADDRESS, config_address(address, offset));
        self.ports.write_u32(CONFIG_DATA, value);
    }
}

static CONFIG_LOCK: IrqSpinMutex<()> = IrqSpinMutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_dword_encodes_bus_device_function_and_aligned_offset() {
        let address = PciAddress::from_boot(0x120b).unwrap();
        // bus 0x12, device 1, function 3, offset 0x16 rounded down to 0x14.
        assert_eq!(config_address(address, 0x16), 0x8012_0b14);
    }
}
