use super::*;
use alloc::vec;
use alloc::vec::Vec;
use axle_types::interrupt::{
    AX_INTERRUPT_MODE_LEGACY, AX_INTERRUPT_MODE_MSI, AX_INTERRUPT_MODE_MSIX,
    AX_INTERRUPT_MODE_VIRTUAL,
};
use axle_types::pci::{
    AX_PCI_BAR_FLAG_MMIO, AX_PCI_CONFIG_FLAG_MMIO, AX_PCI_CONFIG_FLAG_READ_ONLY,
    AX_PCI_INTERRUPT_GROUP_READY, AX_PCI_INTERRUPT_GROUP_RX_COMPLETE,
    AX_PCI_INTERRUPT_GROUP_TX_KICK, AX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE,
    AX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED, AX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE,
    AX_PCI_INTERRUPT_MODE_LEGACY, AX_PCI_INTERRUPT_MODE_MSI, AX_PCI_INTERRUPT_MODE_MSIX,
    AX_PCI_INTERRUPT_MODE_VIRTUAL, AX_PCI_RESOURCE_FLAG_MMIO, AX_PCI_RESOURCE_FLAG_READ_ONLY,
    AX_PCI_RESOURCE_FLAG_TRIGGERABLE, AX_PCI_RESOURCE_KIND_BAR, AX_PCI_RESOURCE_KIND_CONFIG,
    AX_PCI_RESOURCE_KIND_INTERRUPT, ax_pci_bar_info_t, ax_pci_config_info_t, ax_pci_device_info_t,
    ax_pci_interrupt_info_t, ax_pci_interrupt_mode_info_t, ax_pci_resource_info_t,
};
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_NO_MEMORY, ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE,
    ZX_ERR_WRONG_TYPE,
};
use axle_virtio_transport::VirtioPciDiscovery;

pub(crate) const BOOTSTRAP_NET_QUEUE_PAIR_COUNT: usize = 2;
pub(crate) const BOOTSTRAP_NET_QUEUE_SIZE: u32 = 4;
pub(crate) const BOOTSTRAP_NET_INTERRUPT_GROUPS: u32 = 3;
pub(crate) const BOOTSTRAP_NET_BAR0_BYTES: u64 = crate::userspace::USER_PAGE_BYTES;
pub(crate) const BOOTSTRAP_NET_CONFIG_BYTES: u64 = crate::userspace::USER_PAGE_BYTES;
pub(crate) const BOOTSTRAP_NET_VENDOR_ID: u16 = 0x4158;
pub(crate) const BOOTSTRAP_NET_DEVICE_ID: u16 = 0x0001;
pub(crate) const BOOTSTRAP_NET_CLASS_CODE: u8 = 0x02;
pub(crate) const BOOTSTRAP_NET_SUBCLASS_ETHERNET: u8 = 0x00;
pub(crate) const BOOTSTRAP_NET_DEVICE_FEATURES: u32 = 1 << 0;
pub(crate) const BOOTSTRAP_NET_CONFIG_CAP_PTR: usize = 0x40;
pub(crate) const BOOTSTRAP_NET_PCI_STATUS_CAP_LIST: u16 = 1 << 4;
pub(crate) const BOOTSTRAP_NET_PCI_CAP_ID_VENDOR: u8 = 0x09;
pub(crate) const BOOTSTRAP_NET_VIRTIO_CAP_COMMON_CFG: u8 = 1;
pub(crate) const BOOTSTRAP_NET_VIRTIO_CAP_NOTIFY_CFG: u8 = 2;
pub(crate) const BOOTSTRAP_NET_VIRTIO_CAP_ISR_CFG: u8 = 3;
pub(crate) const BOOTSTRAP_NET_VIRTIO_CAP_DEVICE_CFG: u8 = 4;
pub(crate) const BOOTSTRAP_NET_COMMON_CFG_OFFSET: u32 = 0x000;
pub(crate) const BOOTSTRAP_NET_COMMON_CFG_BYTES: u32 = 72;
pub(crate) const BOOTSTRAP_NET_NOTIFY_CFG_OFFSET: u32 = 0x100;
pub(crate) const BOOTSTRAP_NET_NOTIFY_CFG_BYTES: u32 =
    (BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u32 * 2) * 4;
pub(crate) const BOOTSTRAP_NET_NOTIFY_MULTIPLIER: u32 = 4;
pub(crate) const BOOTSTRAP_NET_ISR_CFG_OFFSET: u32 = 0x180;
pub(crate) const BOOTSTRAP_NET_ISR_CFG_BYTES: u32 = 4;
pub(crate) const BOOTSTRAP_NET_DEVICE_CFG_OFFSET: u32 = 0x200;
pub(crate) const BOOTSTRAP_NET_DEVICE_CFG_BYTES: u32 = 8;

const PCI_VENDOR_ID_OFF: usize = 0x00;
const PCI_DEVICE_ID_OFF: usize = 0x02;
const PCI_COMMAND_OFF: usize = 0x04;
const PCI_STATUS_OFF: usize = 0x06;
const PCI_REVISION_ID_OFF: usize = 0x08;
const PCI_PROG_IF_OFF: usize = 0x09;
const PCI_SUBCLASS_OFF: usize = 0x0a;
const PCI_CLASS_CODE_OFF: usize = 0x0b;
const PCI_HEADER_TYPE_OFF: usize = 0x0e;
const PCI_BAR0_OFF: usize = 0x10;
const PCI_CAP_PTR_OFF: usize = 0x34;
const PCI_INTERRUPT_PIN_OFF: usize = 0x3d;

const CAP_COMMON_OFF: usize = BOOTSTRAP_NET_CONFIG_CAP_PTR;
const CAP_NOTIFY_OFF: usize = CAP_COMMON_OFF + 16;
const CAP_ISR_OFF: usize = CAP_NOTIFY_OFF + 20;
const CAP_DEVICE_OFF: usize = CAP_ISR_OFF + 16;
const REAL_NET_CONFIG_BYTES: u64 = crate::userspace::USER_PAGE_BYTES;

fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_virtio_cap(
    bytes: &mut [u8],
    offset: usize,
    next: u8,
    cfg_type: u8,
    bar: u8,
    region_offset: u32,
    region_length: u32,
) {
    bytes[offset] = BOOTSTRAP_NET_PCI_CAP_ID_VENDOR;
    bytes[offset + 1] = next;
    bytes[offset + 2] = 16;
    bytes[offset + 3] = cfg_type;
    bytes[offset + 4] = bar;
    bytes[offset + 5] = 0;
    bytes[offset + 6] = 0;
    bytes[offset + 7] = 0;
    write_u32_le(bytes, offset + 8, region_offset);
    write_u32_le(bytes, offset + 12, region_length);
}

fn write_notify_cap(
    bytes: &mut [u8],
    offset: usize,
    next: u8,
    bar: u8,
    region_offset: u32,
    region_length: u32,
) {
    bytes[offset] = BOOTSTRAP_NET_PCI_CAP_ID_VENDOR;
    bytes[offset + 1] = next;
    bytes[offset + 2] = 20;
    bytes[offset + 3] = BOOTSTRAP_NET_VIRTIO_CAP_NOTIFY_CFG;
    bytes[offset + 4] = bar;
    bytes[offset + 5] = 0;
    bytes[offset + 6] = 0;
    bytes[offset + 7] = 0;
    write_u32_le(bytes, offset + 8, region_offset);
    write_u32_le(bytes, offset + 12, region_length);
    write_u32_le(bytes, offset + 16, BOOTSTRAP_NET_NOTIFY_MULTIPLIER);
}

fn write_bootstrap_net_config_space(bytes: &mut [u8], bar0_paddr: u64) {
    assert_eq!(bytes.len(), BOOTSTRAP_NET_CONFIG_BYTES as usize);
    write_u16_le(bytes, PCI_VENDOR_ID_OFF, BOOTSTRAP_NET_VENDOR_ID);
    write_u16_le(bytes, PCI_DEVICE_ID_OFF, BOOTSTRAP_NET_DEVICE_ID);
    write_u16_le(bytes, PCI_COMMAND_OFF, 0x0006);
    write_u16_le(bytes, PCI_STATUS_OFF, BOOTSTRAP_NET_PCI_STATUS_CAP_LIST);
    bytes[PCI_REVISION_ID_OFF] = 0;
    bytes[PCI_PROG_IF_OFF] = 0;
    bytes[PCI_SUBCLASS_OFF] = BOOTSTRAP_NET_SUBCLASS_ETHERNET;
    bytes[PCI_CLASS_CODE_OFF] = BOOTSTRAP_NET_CLASS_CODE;
    bytes[PCI_HEADER_TYPE_OFF] = 0;
    write_u32_le(bytes, PCI_BAR0_OFF, (bar0_paddr as u32) & !0xf);
    bytes[PCI_CAP_PTR_OFF] = BOOTSTRAP_NET_CONFIG_CAP_PTR as u8;
    bytes[PCI_INTERRUPT_PIN_OFF] = 1;

    write_virtio_cap(
        bytes,
        CAP_COMMON_OFF,
        CAP_NOTIFY_OFF as u8,
        BOOTSTRAP_NET_VIRTIO_CAP_COMMON_CFG,
        0,
        BOOTSTRAP_NET_COMMON_CFG_OFFSET,
        BOOTSTRAP_NET_COMMON_CFG_BYTES,
    );
    write_notify_cap(
        bytes,
        CAP_NOTIFY_OFF,
        CAP_ISR_OFF as u8,
        0,
        BOOTSTRAP_NET_NOTIFY_CFG_OFFSET,
        BOOTSTRAP_NET_NOTIFY_CFG_BYTES,
    );
    write_virtio_cap(
        bytes,
        CAP_ISR_OFF,
        CAP_DEVICE_OFF as u8,
        BOOTSTRAP_NET_VIRTIO_CAP_ISR_CFG,
        0,
        BOOTSTRAP_NET_ISR_CFG_OFFSET,
        BOOTSTRAP_NET_ISR_CFG_BYTES,
    );
    write_virtio_cap(
        bytes,
        CAP_DEVICE_OFF,
        0,
        BOOTSTRAP_NET_VIRTIO_CAP_DEVICE_CFG,
        0,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET,
        BOOTSTRAP_NET_DEVICE_CFG_BYTES,
    );
    write_u16_le(
        bytes,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET as usize,
        BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u16,
    );
    write_u16_le(
        bytes,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET as usize + 2,
        BOOTSTRAP_NET_QUEUE_SIZE as u16,
    );
    write_u32_le(
        bytes,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET as usize + 4,
        BOOTSTRAP_NET_DEVICE_FEATURES,
    );
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PciBarResource {
    pub(crate) index: u32,
    pub(crate) object: ObjectKey,
    pub(crate) backing_object: Option<ObjectKey>,
    pub(crate) size: u64,
    pub(crate) flags: u32,
    pub(crate) map_options: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PciInterruptResource {
    pub(crate) group: u32,
    pub(crate) queue_pair: u32,
    pub(crate) object: ObjectKey,
}

#[derive(Debug)]
pub(crate) struct PciDeviceObject {
    pub(crate) location: Option<crate::arch::x86_64::pci::PciFunctionLocation>,
    pub(crate) vendor_id: u16,
    pub(crate) device_id: u16,
    pub(crate) prog_if: u8,
    pub(crate) subclass: u8,
    pub(crate) class_code: u8,
    pub(crate) revision_id: u8,
    pub(crate) config_object: ObjectKey,
    pub(crate) config_backing_object: ObjectKey,
    pub(crate) config_size: u64,
    pub(crate) bars: Vec<PciBarResource>,
    pub(crate) device_features: u32,
    pub(crate) queue_pairs: u32,
    pub(crate) queue_size: u32,
    pub(crate) interrupt_groups: u32,
    pub(crate) active_interrupt_mode: u32,
    pub(crate) interrupts: Vec<PciInterruptResource>,
}

impl PciDeviceObject {
    fn resource_count(&self) -> u32 {
        1 + self.bars.len() as u32 + self.interrupts.len() as u32
    }

    fn info(&self) -> ax_pci_device_info_t {
        ax_pci_device_info_t {
            vendor_id: self.vendor_id,
            device_id: self.device_id,
            prog_if: self.prog_if,
            subclass: self.subclass,
            class_code: self.class_code,
            revision_id: self.revision_id,
            bar_count: self.bars.len() as u32,
            queue_pairs: self.queue_pairs,
            queue_size: self.queue_size,
            device_features: self.device_features,
            interrupt_groups: self.interrupt_groups,
            reserved0: 0,
        }
    }

    fn config(&self) -> (ObjectKey, ax_pci_config_info_t) {
        (
            self.config_object,
            ax_pci_config_info_t {
                handle: ZX_HANDLE_INVALID,
                size: self.config_size,
                flags: AX_PCI_CONFIG_FLAG_MMIO | AX_PCI_CONFIG_FLAG_READ_ONLY,
                map_options: axle_types::vm::AX_VM_MAP_MMIO,
            },
        )
    }

    fn bar(&self, bar_index: u32) -> Result<(ObjectKey, ax_pci_bar_info_t), zx_status_t> {
        let bar = self
            .bars
            .iter()
            .find(|bar| bar.index == bar_index)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok((
            bar.object,
            ax_pci_bar_info_t {
                handle: ZX_HANDLE_INVALID,
                size: bar.size,
                flags: bar.flags,
                map_options: bar.map_options,
            },
        ))
    }

    fn interrupt_triggerable(mode: u32) -> bool {
        mode == AX_PCI_INTERRUPT_MODE_VIRTUAL
    }

    fn interrupt_vector(&self, mode: u32, group: u32, queue_pair: u32) -> u32 {
        if self.interrupt_groups == 0 || self.queue_pairs == 0 {
            return 0;
        }
        match mode {
            AX_PCI_INTERRUPT_MODE_LEGACY => 0,
            AX_PCI_INTERRUPT_MODE_VIRTUAL
            | AX_PCI_INTERRUPT_MODE_MSI
            | AX_PCI_INTERRUPT_MODE_MSIX => group
                .saturating_mul(self.queue_pairs)
                .saturating_add(queue_pair),
            _ => 0,
        }
    }

    fn interrupt_mode_for_object(mode: u32) -> Result<u32, zx_status_t> {
        match mode {
            AX_PCI_INTERRUPT_MODE_VIRTUAL => Ok(AX_INTERRUPT_MODE_VIRTUAL),
            AX_PCI_INTERRUPT_MODE_LEGACY => Ok(AX_INTERRUPT_MODE_LEGACY),
            AX_PCI_INTERRUPT_MODE_MSI => Ok(AX_INTERRUPT_MODE_MSI),
            AX_PCI_INTERRUPT_MODE_MSIX => Ok(AX_INTERRUPT_MODE_MSIX),
            _ => Err(ZX_ERR_OUT_OF_RANGE),
        }
    }

    fn interrupt_resource(
        &self,
        ordinal: u32,
    ) -> Result<(ObjectKey, ax_pci_resource_info_t), zx_status_t> {
        let interrupt = self
            .interrupts
            .get(ordinal as usize)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let triggerable = Self::interrupt_triggerable(self.active_interrupt_mode);
        Ok((
            interrupt.object,
            ax_pci_resource_info_t {
                handle: ZX_HANDLE_INVALID,
                kind: AX_PCI_RESOURCE_KIND_INTERRUPT,
                index: interrupt.group,
                subindex: interrupt.queue_pair,
                flags: if triggerable {
                    AX_PCI_RESOURCE_FLAG_TRIGGERABLE
                } else {
                    0
                },
                map_options: 0,
                size: 0,
                mode: self.active_interrupt_mode,
                vector: self.interrupt_vector(
                    self.active_interrupt_mode,
                    interrupt.group,
                    interrupt.queue_pair,
                ),
                reserved0: 0,
            },
        ))
    }

    fn resource(&self, ordinal: u32) -> Result<(ObjectKey, ax_pci_resource_info_t), zx_status_t> {
        if ordinal == 0 {
            return Ok((
                self.config_object,
                ax_pci_resource_info_t {
                    handle: ZX_HANDLE_INVALID,
                    kind: AX_PCI_RESOURCE_KIND_CONFIG,
                    index: 0,
                    subindex: 0,
                    flags: AX_PCI_RESOURCE_FLAG_MMIO | AX_PCI_RESOURCE_FLAG_READ_ONLY,
                    map_options: axle_types::vm::AX_VM_MAP_MMIO,
                    size: self.config_size,
                    mode: 0,
                    vector: 0,
                    reserved0: 0,
                },
            ));
        }
        let ordinal = ordinal - 1;
        if let Some(bar) = self.bars.get(ordinal as usize) {
            return Ok((
                bar.object,
                ax_pci_resource_info_t {
                    handle: ZX_HANDLE_INVALID,
                    kind: AX_PCI_RESOURCE_KIND_BAR,
                    index: bar.index,
                    subindex: 0,
                    flags: if (bar.flags & AX_PCI_BAR_FLAG_MMIO) != 0 {
                        AX_PCI_RESOURCE_FLAG_MMIO
                    } else {
                        0
                    },
                    map_options: bar.map_options,
                    size: bar.size,
                    mode: 0,
                    vector: 0,
                    reserved0: 0,
                },
            ));
        }
        self.interrupt_resource(ordinal - self.bars.len() as u32)
    }

    fn interrupt_key(&self, group: u32, queue_pair: u32) -> Result<ObjectKey, zx_status_t> {
        self.interrupts
            .iter()
            .find(|interrupt| interrupt.group == group && interrupt.queue_pair == queue_pair)
            .map(|interrupt| interrupt.object)
            .ok_or(ZX_ERR_OUT_OF_RANGE)
    }

    fn interrupt_mode_info(&self, mode: u32) -> Result<ax_pci_interrupt_mode_info_t, zx_status_t> {
        if self.interrupts.is_empty() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let vector_count = match mode {
            AX_PCI_INTERRUPT_MODE_LEGACY => 1,
            AX_PCI_INTERRUPT_MODE_VIRTUAL
            | AX_PCI_INTERRUPT_MODE_MSI
            | AX_PCI_INTERRUPT_MODE_MSIX => self.interrupt_groups * self.queue_pairs,
            _ => return Err(ZX_ERR_OUT_OF_RANGE),
        };
        let info = match mode {
            AX_PCI_INTERRUPT_MODE_VIRTUAL => ax_pci_interrupt_mode_info_t {
                mode,
                flags: AX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED
                    | AX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE
                    | if self.active_interrupt_mode == AX_PCI_INTERRUPT_MODE_VIRTUAL {
                        AX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE
                    } else {
                        0
                    },
                base_vector: 0,
                vector_count,
            },
            AX_PCI_INTERRUPT_MODE_LEGACY
            | AX_PCI_INTERRUPT_MODE_MSI
            | AX_PCI_INTERRUPT_MODE_MSIX => ax_pci_interrupt_mode_info_t {
                mode,
                flags: AX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED
                    | if self.active_interrupt_mode == mode {
                        AX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE
                    } else {
                        0
                    },
                base_vector: 0,
                vector_count,
            },
            _ => return Err(ZX_ERR_OUT_OF_RANGE),
        };
        Ok(info)
    }
}

pub fn bootstrap_net_pci_device_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_net_pci_device_handle != 0)
                .then_some(registry.bootstrap_net_pci_device_handle))
        })
    })
    .ok()
    .flatten()
}

pub fn bootstrap_real_net_pci_device_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_real_net_pci_device_handle != 0)
                .then_some(registry.bootstrap_real_net_pci_device_handle))
        })
    })
    .ok()
    .flatten()
}

pub(crate) fn seed_bootstrap_net_pci_device(state: &KernelState) -> Result<(), zx_status_t> {
    let already_seeded =
        state.with_registry(|registry| Ok(registry.bootstrap_net_pci_device_handle))?;
    if already_seeded != 0 {
        return Ok(());
    }

    let process_id = state.with_core(|kernel| Ok(kernel.current_process_info()?.process_id()))?;
    let config_backing_object = create_global_vmo_object(
        state,
        process_id,
        axle_mm::VmoKind::Contiguous,
        |vm, global_vmo_id| {
            vm.create_contiguous_vmo_global(BOOTSTRAP_NET_CONFIG_BYTES, global_vmo_id)
        },
    )?;
    let config_backing_vmo = lookup_vmo_object(state, config_backing_object)?;
    let bar0_backing_object = create_global_vmo_object(
        state,
        process_id,
        axle_mm::VmoKind::Contiguous,
        |vm, global_vmo_id| {
            vm.create_contiguous_vmo_global(BOOTSTRAP_NET_BAR0_BYTES, global_vmo_id)
        },
    )?;
    let bar0_backing_vmo = lookup_vmo_object(state, bar0_backing_object)?;
    let bar0_paddr = state.with_vm_mut(|vm| vm.lookup_vmo_paddr(&bar0_backing_vmo, 0))?;
    let mut config_bytes = Vec::new();
    config_bytes
        .try_reserve_exact(BOOTSTRAP_NET_CONFIG_BYTES as usize)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    config_bytes.resize(BOOTSTRAP_NET_CONFIG_BYTES as usize, 0);
    write_bootstrap_net_config_space(&mut config_bytes, bar0_paddr);
    state.with_vm_mut(|vm| vm.write_vmo_bytes(&config_backing_vmo, 0, &config_bytes))?;
    let config_paddr = state.with_vm_mut(|vm| vm.lookup_vmo_paddr(&config_backing_vmo, 0))?;
    let config_object = create_global_vmo_object(
        state,
        process_id,
        axle_mm::VmoKind::Physical,
        |vm, global_vmo_id| {
            vm.create_physical_vmo_global(config_paddr, BOOTSTRAP_NET_CONFIG_BYTES, global_vmo_id)
        },
    )?;
    let bar0_object = create_global_vmo_object(
        state,
        process_id,
        axle_mm::VmoKind::Physical,
        |vm, global_vmo_id| {
            vm.create_physical_vmo_global(bar0_paddr, BOOTSTRAP_NET_BAR0_BYTES, global_vmo_id)
        },
    )?;

    let ready_irqs = create_interrupt_array(state, AX_PCI_INTERRUPT_GROUP_READY)?;
    let tx_irqs = create_interrupt_array(state, AX_PCI_INTERRUPT_GROUP_TX_KICK)?;
    let rx_irqs = create_interrupt_array(state, AX_PCI_INTERRUPT_GROUP_RX_COMPLETE)?;

    let object_id = state.alloc_object_id();
    state.with_registry_mut(|registry| {
        registry.insert(
            object_id,
            KernelObject::PciDevice(build_synthetic_net_pci_device(
                config_object,
                config_backing_object,
                bar0_object,
                bar0_backing_object,
                ready_irqs,
                tx_irqs,
                rx_irqs,
            )),
        )?;
        Ok(())
    })?;
    let handle = state.alloc_handle_for_object(object_id, handle::pci_device_default_rights())?;
    state.with_registry_mut(|registry| {
        registry.bootstrap_net_pci_device_handle = handle;
        Ok(())
    })?;
    Ok(())
}

pub(crate) fn seed_real_net_pci_device(state: &KernelState) -> Result<(), zx_status_t> {
    let already_seeded =
        state.with_registry(|registry| Ok(registry.bootstrap_real_net_pci_device_handle))?;
    if already_seeded != 0 {
        return Ok(());
    }

    let Some(function) = crate::arch::x86_64::pci::find_first_network_function() else {
        return Ok(());
    };
    let Some(discovery) = axle_virtio_transport::discover_pci_transport(&function.config_space)
    else {
        return Ok(());
    };
    let Some(device) = build_real_net_pci_device(state, function, discovery)? else {
        return Ok(());
    };

    let object_id = state.alloc_object_id();
    state.with_registry_mut(|registry| {
        registry.insert(object_id, KernelObject::PciDevice(device))?;
        Ok(())
    })?;
    let handle = state.alloc_handle_for_object(object_id, handle::pci_device_default_rights())?;
    state.with_registry_mut(|registry| {
        registry.bootstrap_real_net_pci_device_handle = handle;
        Ok(())
    })?;
    Ok(())
}

fn build_synthetic_net_pci_device(
    config_object: ObjectKey,
    config_backing_object: ObjectKey,
    bar0_object: ObjectKey,
    bar0_backing_object: ObjectKey,
    ready_irqs: [ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT],
    tx_irqs: [ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT],
    rx_irqs: [ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT],
) -> PciDeviceObject {
    let bars = vec![PciBarResource {
        index: 0,
        object: bar0_object,
        backing_object: Some(bar0_backing_object),
        size: BOOTSTRAP_NET_BAR0_BYTES,
        flags: AX_PCI_BAR_FLAG_MMIO,
        map_options: axle_types::vm::AX_VM_MAP_MMIO,
    }];
    let mut interrupts = Vec::with_capacity(
        BOOTSTRAP_NET_INTERRUPT_GROUPS as usize * BOOTSTRAP_NET_QUEUE_PAIR_COUNT,
    );
    for (group, keys) in [
        (AX_PCI_INTERRUPT_GROUP_READY, ready_irqs),
        (AX_PCI_INTERRUPT_GROUP_TX_KICK, tx_irqs),
        (AX_PCI_INTERRUPT_GROUP_RX_COMPLETE, rx_irqs),
    ] {
        for (pair, key) in keys.into_iter().enumerate() {
            interrupts.push(PciInterruptResource {
                group,
                queue_pair: pair as u32,
                object: key,
            });
        }
    }
    PciDeviceObject {
        location: None,
        vendor_id: BOOTSTRAP_NET_VENDOR_ID,
        device_id: BOOTSTRAP_NET_DEVICE_ID,
        prog_if: 0,
        subclass: BOOTSTRAP_NET_SUBCLASS_ETHERNET,
        class_code: BOOTSTRAP_NET_CLASS_CODE,
        revision_id: 0,
        config_object,
        config_backing_object,
        config_size: BOOTSTRAP_NET_CONFIG_BYTES,
        bars,
        device_features: BOOTSTRAP_NET_DEVICE_FEATURES,
        queue_pairs: BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u32,
        queue_size: BOOTSTRAP_NET_QUEUE_SIZE,
        interrupt_groups: BOOTSTRAP_NET_INTERRUPT_GROUPS,
        active_interrupt_mode: AX_PCI_INTERRUPT_MODE_VIRTUAL,
        interrupts,
    }
}

fn build_real_net_pci_device(
    state: &KernelState,
    function: crate::arch::x86_64::pci::PciFunctionInfo,
    discovery: VirtioPciDiscovery,
) -> Result<Option<PciDeviceObject>, zx_status_t> {
    let process_id = state.with_core(|kernel| Ok(kernel.current_process_info()?.process_id()))?;
    let config_backing_object = create_global_vmo_object(
        state,
        process_id,
        axle_mm::VmoKind::Contiguous,
        |vm, global_vmo_id| vm.create_contiguous_vmo_global(REAL_NET_CONFIG_BYTES, global_vmo_id),
    )?;
    let config_backing_vmo = lookup_vmo_object(state, config_backing_object)?;
    state.with_vm_mut(|vm| vm.write_vmo_bytes(&config_backing_vmo, 0, &function.config_space))?;
    let config_paddr = state.with_vm_mut(|vm| vm.lookup_vmo_paddr(&config_backing_vmo, 0))?;
    let config_object = create_global_vmo_object(
        state,
        process_id,
        axle_mm::VmoKind::Physical,
        |vm, global_vmo_id| {
            vm.create_physical_vmo_global(config_paddr, REAL_NET_CONFIG_BYTES, global_vmo_id)
        },
    )?;

    let required_bars = required_virtio_bar_bytes(discovery);
    let mut bars = Vec::with_capacity(required_bars.len());
    for (bar_index, size) in required_bars {
        let Some(base_paddr) = decode_bar_paddr(&function.bars, bar_index as usize) else {
            continue;
        };
        let object = create_global_vmo_object(
            state,
            process_id,
            axle_mm::VmoKind::Physical,
            |vm, global_vmo_id| vm.create_physical_vmo_global(base_paddr, size, global_vmo_id),
        )?;
        bars.push(PciBarResource {
            index: bar_index,
            object,
            backing_object: None,
            size,
            flags: AX_PCI_BAR_FLAG_MMIO,
            map_options: axle_types::vm::AX_VM_MAP_MMIO,
        });
    }

    if bars.is_empty() {
        return Ok(None);
    }

    Ok(Some(PciDeviceObject {
        location: Some(function.location),
        vendor_id: function.vendor_id,
        device_id: function.device_id,
        prog_if: function.prog_if,
        subclass: function.subclass,
        class_code: function.class_code,
        revision_id: function.config_space[PCI_REVISION_ID_OFF],
        config_object,
        config_backing_object,
        config_size: REAL_NET_CONFIG_BYTES,
        bars,
        device_features: 0,
        queue_pairs: 0,
        queue_size: 0,
        interrupt_groups: 0,
        active_interrupt_mode: AX_PCI_INTERRUPT_MODE_VIRTUAL,
        interrupts: Vec::new(),
    }))
}

fn required_virtio_bar_bytes(discovery: VirtioPciDiscovery) -> Vec<(u32, u64)> {
    let mut by_bar = BTreeMap::<u32, u64>::new();
    for region in [
        discovery.common,
        discovery.notify,
        discovery.isr,
        discovery.device,
    ] {
        let end = u64::from(region.offset).saturating_add(u64::from(region.length));
        let entry = by_bar.entry(u32::from(region.bar)).or_insert(0);
        *entry = (*entry).max(end);
    }
    by_bar
        .into_iter()
        .filter_map(|(bar_index, end)| {
            let rounded = round_up_to_page(end.max(crate::userspace::USER_PAGE_BYTES))?;
            Some((bar_index, rounded))
        })
        .collect()
}

fn round_up_to_page(value: u64) -> Option<u64> {
    let page = crate::userspace::USER_PAGE_BYTES;
    let mask = page.checked_sub(1)?;
    value.checked_add(mask).map(|rounded| rounded & !mask)
}

fn decode_bar_paddr(raw_bars: &[u32; 6], index: usize) -> Option<u64> {
    let raw = *raw_bars.get(index)?;
    if raw == 0 || (raw & 0x1) != 0 {
        return None;
    }
    let bar_type = (raw >> 1) & 0x3;
    let base_low = u64::from(raw & !0xf);
    match bar_type {
        0x0 => Some(base_low),
        0x2 => {
            let high = u64::from(*raw_bars.get(index + 1)?);
            Some(base_low | (high << 32))
        }
        _ => None,
    }
}

pub fn pci_device_get_info(handle: zx_handle_t) -> Result<ax_pci_device_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::PciDevice(device)) => Ok(device.info()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

pub fn pci_device_get_config(handle: zx_handle_t) -> Result<ax_pci_config_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        let (config_object, mut info) =
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => Ok(device.config()),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;
        let config_handle =
            state.alloc_handle_for_object(config_object, handle::pci_config_vmo_rights())?;
        info.handle = config_handle;
        Ok(info)
    })
}

pub fn pci_device_get_bar(
    handle: zx_handle_t,
    bar_index: u32,
) -> Result<ax_pci_bar_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        let (bar_object, mut info) =
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => device.bar(bar_index),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;
        let bar_handle = state.alloc_handle_for_object(bar_object, handle::vmo_default_rights())?;
        info.handle = bar_handle;
        Ok(info)
    })
}

pub fn pci_device_get_interrupt(
    handle: zx_handle_t,
    group: u32,
    queue_pair: u32,
) -> Result<ax_pci_interrupt_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        let (irq_object, mode) =
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => Ok((
                    device.interrupt_key(group, queue_pair)?,
                    device.active_interrupt_mode,
                )),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;
        let irq_handle =
            state.alloc_handle_for_object(irq_object, handle::interrupt_default_rights())?;
        Ok(ax_pci_interrupt_info_t {
            handle: irq_handle,
            mode,
            vector: state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => {
                    Ok(device.interrupt_vector(mode, group, queue_pair))
                }
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?,
        })
    })
}

pub fn pci_device_get_resource_count(handle: zx_handle_t) -> Result<u32, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::PciDevice(device)) => Ok(device.resource_count()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

pub fn pci_device_get_resource(
    handle: zx_handle_t,
    resource_index: u32,
) -> Result<ax_pci_resource_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        let (resource_object, mut info) =
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => device.resource(resource_index),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;
        let rights = match info.kind {
            AX_PCI_RESOURCE_KIND_CONFIG => handle::pci_config_vmo_rights(),
            AX_PCI_RESOURCE_KIND_BAR => handle::vmo_default_rights(),
            AX_PCI_RESOURCE_KIND_INTERRUPT => handle::interrupt_default_rights(),
            _ => return Err(ZX_ERR_BAD_STATE),
        };
        info.handle = state.alloc_handle_for_object(resource_object, rights)?;
        Ok(info)
    })
}

pub fn pci_device_get_interrupt_mode(
    handle: zx_handle_t,
    mode: u32,
) -> Result<ax_pci_interrupt_mode_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::PciDevice(device)) => device.interrupt_mode_info(mode),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

pub fn pci_device_set_interrupt_mode(handle: zx_handle_t, mode: u32) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        state.with_objects_mut(|objects| {
            let interrupts = match objects.get_mut(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => {
                    let _ = PciDeviceObject::interrupt_mode_info(device, mode)?;
                    device.active_interrupt_mode = mode;
                    device.interrupts.clone()
                }
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };

            let interrupt_mode = PciDeviceObject::interrupt_mode_for_object(mode)?;
            let triggerable = PciDeviceObject::interrupt_triggerable(mode);
            let queue_pairs = interrupts
                .iter()
                .map(|interrupt| interrupt.queue_pair)
                .max()
                .map_or(0, |pair| pair.saturating_add(1));
            for interrupt in interrupts {
                let vector = match mode {
                    AX_PCI_INTERRUPT_MODE_LEGACY => 0,
                    _ => interrupt
                        .group
                        .saturating_mul(queue_pairs)
                        .saturating_add(interrupt.queue_pair),
                };
                match objects.get_mut(interrupt.object) {
                    Some(KernelObject::Interrupt(interrupt_object)) => {
                        interrupt_object.set_metadata(interrupt_mode, vector, triggerable);
                    }
                    Some(_) => return Err(ZX_ERR_BAD_STATE),
                    None => return Err(ZX_ERR_BAD_STATE),
                }
            }
            Ok(())
        })
    })
}

pub fn pci_device_set_command(handle: zx_handle_t, command: u16) -> Result<(), zx_status_t> {
    // Whitelist of safe PCI command register bits that userspace may toggle.
    // Bit 0: I/O Space Enable
    // Bit 1: Memory Space Enable
    // Bit 2: Bus Master Enable
    const PCI_COMMAND_SAFE_MASK: u16 = 0x0007;

    let command = command & PCI_COMMAND_SAFE_MASK;

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let (location, config_backing_object) =
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => Ok((
                    device.location.ok_or(ZX_ERR_NOT_SUPPORTED)?,
                    device.config_backing_object,
                )),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;

        crate::arch::x86_64::pci::write_config_u16(location, PCI_COMMAND_OFF as u16, command)
            .ok_or(ZX_ERR_NOT_SUPPORTED)?;

        let config_backing_vmo = lookup_vmo_object(state, config_backing_object)?;
        state.with_vm_mut(|vm| {
            vm.write_vmo_bytes(
                &config_backing_vmo,
                PCI_COMMAND_OFF as u64,
                &command.to_le_bytes(),
            )
        })?;
        Ok(())
    })
}

pub(crate) fn release_pci_device_resources(state: &KernelState, device: PciDeviceObject) {
    let mut registry = state.registry.lock();
    registry.release_kernel_ref(device.config_object);
    registry.release_kernel_ref(device.config_backing_object);
    for bar in device.bars {
        registry.release_kernel_ref(bar.object);
        if let Some(backing) = bar.backing_object {
            registry.release_kernel_ref(backing);
        }
    }
    for interrupt in device.interrupts {
        registry.release_kernel_ref(interrupt.object);
    }
}

fn create_interrupt_array(
    state: &KernelState,
    group: u32,
) -> Result<[ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT], zx_status_t> {
    let mut keys = [ObjectKey::INVALID; BOOTSTRAP_NET_QUEUE_PAIR_COUNT];
    for (pair, key) in keys.iter_mut().enumerate() {
        *key = create_interrupt_object(
            state,
            AX_PCI_INTERRUPT_MODE_VIRTUAL,
            group
                .saturating_mul(BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u32)
                .saturating_add(pair as u32),
        )?;
    }
    Ok(keys)
}

fn create_interrupt_object(
    state: &KernelState,
    mode: u32,
    vector: u32,
) -> Result<ObjectKey, zx_status_t> {
    let object_id = state.alloc_object_id();
    state.with_registry_mut(|registry| {
        registry.insert(
            object_id,
            KernelObject::Interrupt(InterruptObject::new(mode, vector, true)),
        )?;
        registry.retain_kernel_ref(object_id)?;
        Ok(())
    })?;
    Ok(object_id)
}

fn create_global_vmo_object<F>(
    state: &KernelState,
    creator_process_id: u64,
    kind: axle_mm::VmoKind,
    create: F,
) -> Result<ObjectKey, zx_status_t>
where
    F: FnOnce(&crate::task::VmFacade, axle_mm::GlobalVmoId) -> Result<u64, zx_status_t>,
{
    let object_id = state.alloc_object_id();
    let global_vmo_id = state.with_kernel_mut(|kernel| Ok(kernel.allocate_global_vmo_id()))?;
    let size_bytes = state.with_vm_mut(|vm| create(vm, global_vmo_id))?;
    state.with_registry_mut(|registry| {
        registry.insert(
            object_id,
            KernelObject::Vmo(VmoObject {
                creator_process_id,
                global_vmo_id,
                backing_scope: VmoBackingScope::GlobalShared,
                kind,
                size_bytes,
                image_layout: None,
            }),
        )?;
        registry.retain_kernel_ref(object_id)?;
        Ok(())
    })?;
    Ok(object_id)
}

fn lookup_vmo_object(state: &KernelState, object_key: ObjectKey) -> Result<VmoObject, zx_status_t> {
    state.with_objects(|objects| match objects.get(object_key) {
        Some(KernelObject::Vmo(vmo)) => Ok(vmo.clone()),
        Some(_) => Err(ZX_ERR_WRONG_TYPE),
        None => Err(ZX_ERR_BAD_HANDLE),
    })
}
