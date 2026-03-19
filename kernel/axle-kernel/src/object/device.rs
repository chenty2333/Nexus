use super::*;
use axle_types::pci::{
    AX_PCI_BAR_FLAG_MMIO, AX_PCI_CONFIG_FLAG_MMIO, AX_PCI_CONFIG_FLAG_READ_ONLY,
    AX_PCI_INTERRUPT_GROUP_READY, AX_PCI_INTERRUPT_GROUP_RX_COMPLETE,
    AX_PCI_INTERRUPT_GROUP_TX_KICK, AX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE,
    AX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED, AX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE,
    AX_PCI_INTERRUPT_MODE_LEGACY, AX_PCI_INTERRUPT_MODE_MSI, AX_PCI_INTERRUPT_MODE_MSIX,
    AX_PCI_INTERRUPT_MODE_VIRTUAL, ax_pci_bar_info_t, ax_pci_config_info_t, ax_pci_device_info_t,
    ax_pci_interrupt_info_t, ax_pci_interrupt_mode_info_t,
};
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE, ZX_ERR_WRONG_TYPE,
};

pub(crate) const BOOTSTRAP_NET_QUEUE_PAIR_COUNT: usize = 2;
pub(crate) const BOOTSTRAP_NET_QUEUE_SIZE: u32 = 4;
pub(crate) const BOOTSTRAP_NET_BAR_COUNT: u32 = 1;
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

fn build_bootstrap_net_config_space(bar0_paddr: u64) -> [u8; BOOTSTRAP_NET_CONFIG_BYTES as usize] {
    let mut bytes = [0u8; BOOTSTRAP_NET_CONFIG_BYTES as usize];
    write_u16_le(&mut bytes, PCI_VENDOR_ID_OFF, BOOTSTRAP_NET_VENDOR_ID);
    write_u16_le(&mut bytes, PCI_DEVICE_ID_OFF, BOOTSTRAP_NET_DEVICE_ID);
    write_u16_le(&mut bytes, PCI_COMMAND_OFF, 0x0006);
    write_u16_le(
        &mut bytes,
        PCI_STATUS_OFF,
        BOOTSTRAP_NET_PCI_STATUS_CAP_LIST,
    );
    bytes[PCI_REVISION_ID_OFF] = 0;
    bytes[PCI_PROG_IF_OFF] = 0;
    bytes[PCI_SUBCLASS_OFF] = BOOTSTRAP_NET_SUBCLASS_ETHERNET;
    bytes[PCI_CLASS_CODE_OFF] = BOOTSTRAP_NET_CLASS_CODE;
    bytes[PCI_HEADER_TYPE_OFF] = 0;
    write_u32_le(&mut bytes, PCI_BAR0_OFF, (bar0_paddr as u32) & !0xf);
    bytes[PCI_CAP_PTR_OFF] = BOOTSTRAP_NET_CONFIG_CAP_PTR as u8;
    bytes[PCI_INTERRUPT_PIN_OFF] = 1;

    write_virtio_cap(
        &mut bytes,
        CAP_COMMON_OFF,
        CAP_NOTIFY_OFF as u8,
        BOOTSTRAP_NET_VIRTIO_CAP_COMMON_CFG,
        0,
        BOOTSTRAP_NET_COMMON_CFG_OFFSET,
        BOOTSTRAP_NET_COMMON_CFG_BYTES,
    );
    write_notify_cap(
        &mut bytes,
        CAP_NOTIFY_OFF,
        CAP_ISR_OFF as u8,
        0,
        BOOTSTRAP_NET_NOTIFY_CFG_OFFSET,
        BOOTSTRAP_NET_NOTIFY_CFG_BYTES,
    );
    write_virtio_cap(
        &mut bytes,
        CAP_ISR_OFF,
        CAP_DEVICE_OFF as u8,
        BOOTSTRAP_NET_VIRTIO_CAP_ISR_CFG,
        0,
        BOOTSTRAP_NET_ISR_CFG_OFFSET,
        BOOTSTRAP_NET_ISR_CFG_BYTES,
    );
    write_virtio_cap(
        &mut bytes,
        CAP_DEVICE_OFF,
        0,
        BOOTSTRAP_NET_VIRTIO_CAP_DEVICE_CFG,
        0,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET,
        BOOTSTRAP_NET_DEVICE_CFG_BYTES,
    );
    write_u16_le(
        &mut bytes,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET as usize,
        BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u16,
    );
    write_u16_le(
        &mut bytes,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET as usize + 2,
        BOOTSTRAP_NET_QUEUE_SIZE as u16,
    );
    write_u32_le(
        &mut bytes,
        BOOTSTRAP_NET_DEVICE_CFG_OFFSET as usize + 4,
        BOOTSTRAP_NET_DEVICE_FEATURES,
    );
    bytes
}

#[derive(Debug)]
pub(crate) struct PciDeviceObject {
    pub(crate) vendor_id: u16,
    pub(crate) device_id: u16,
    pub(crate) prog_if: u8,
    pub(crate) subclass: u8,
    pub(crate) class_code: u8,
    pub(crate) revision_id: u8,
    pub(crate) config_object: ObjectKey,
    pub(crate) config_backing_object: ObjectKey,
    pub(crate) config_size: u64,
    pub(crate) bar0_object: ObjectKey,
    pub(crate) bar0_backing_object: ObjectKey,
    pub(crate) bar0_size: u64,
    pub(crate) device_features: u32,
    pub(crate) queue_pairs: u32,
    pub(crate) queue_size: u32,
    pub(crate) active_interrupt_mode: u32,
    pub(crate) ready_irqs: [ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT],
    pub(crate) tx_irqs: [ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT],
    pub(crate) rx_irqs: [ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT],
}

impl PciDeviceObject {
    fn info(&self) -> ax_pci_device_info_t {
        ax_pci_device_info_t {
            vendor_id: self.vendor_id,
            device_id: self.device_id,
            prog_if: self.prog_if,
            subclass: self.subclass,
            class_code: self.class_code,
            revision_id: self.revision_id,
            bar_count: BOOTSTRAP_NET_BAR_COUNT,
            queue_pairs: self.queue_pairs,
            queue_size: self.queue_size,
            device_features: self.device_features,
            interrupt_groups: BOOTSTRAP_NET_INTERRUPT_GROUPS,
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
        if bar_index != 0 {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        Ok((
            self.bar0_object,
            ax_pci_bar_info_t {
                handle: ZX_HANDLE_INVALID,
                size: self.bar0_size,
                flags: AX_PCI_BAR_FLAG_MMIO,
                map_options: axle_types::vm::AX_VM_MAP_MMIO,
            },
        ))
    }

    fn interrupt_key(&self, group: u32, queue_pair: u32) -> Result<ObjectKey, zx_status_t> {
        let pair = usize::try_from(queue_pair).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        if pair >= BOOTSTRAP_NET_QUEUE_PAIR_COUNT {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        match group {
            AX_PCI_INTERRUPT_GROUP_READY => Ok(self.ready_irqs[pair]),
            AX_PCI_INTERRUPT_GROUP_TX_KICK => Ok(self.tx_irqs[pair]),
            AX_PCI_INTERRUPT_GROUP_RX_COMPLETE => Ok(self.rx_irqs[pair]),
            _ => Err(ZX_ERR_OUT_OF_RANGE),
        }
    }

    fn interrupt_mode_info(&self, mode: u32) -> Result<ax_pci_interrupt_mode_info_t, zx_status_t> {
        let vector_count = BOOTSTRAP_NET_INTERRUPT_GROUPS * self.queue_pairs;
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
                flags: 0,
                base_vector: 0,
                vector_count: 0,
            },
            _ => return Err(ZX_ERR_OUT_OF_RANGE),
        };
        Ok(info)
    }

    fn set_interrupt_mode(&mut self, mode: u32) -> Result<(), zx_status_t> {
        match mode {
            AX_PCI_INTERRUPT_MODE_VIRTUAL => {
                self.active_interrupt_mode = mode;
                Ok(())
            }
            AX_PCI_INTERRUPT_MODE_LEGACY
            | AX_PCI_INTERRUPT_MODE_MSI
            | AX_PCI_INTERRUPT_MODE_MSIX => Err(ZX_ERR_NOT_SUPPORTED),
            _ => Err(ZX_ERR_OUT_OF_RANGE),
        }
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
    let config_bytes = build_bootstrap_net_config_space(bar0_paddr);
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
            KernelObject::PciDevice(PciDeviceObject {
                vendor_id: BOOTSTRAP_NET_VENDOR_ID,
                device_id: BOOTSTRAP_NET_DEVICE_ID,
                prog_if: 0,
                subclass: BOOTSTRAP_NET_SUBCLASS_ETHERNET,
                class_code: BOOTSTRAP_NET_CLASS_CODE,
                revision_id: 0,
                config_object,
                config_backing_object,
                config_size: BOOTSTRAP_NET_CONFIG_BYTES,
                bar0_object,
                bar0_backing_object,
                bar0_size: BOOTSTRAP_NET_BAR0_BYTES,
                device_features: BOOTSTRAP_NET_DEVICE_FEATURES,
                queue_pairs: BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u32,
                queue_size: BOOTSTRAP_NET_QUEUE_SIZE,
                active_interrupt_mode: AX_PCI_INTERRUPT_MODE_VIRTUAL,
                ready_irqs,
                tx_irqs,
                rx_irqs,
            }),
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
        let vector = group
            .saturating_mul(BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u32)
            .saturating_add(queue_pair);
        Ok(ax_pci_interrupt_info_t {
            handle: irq_handle,
            mode,
            vector,
        })
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
        state.with_objects_mut(|objects| match objects.get_mut(resolved.object_key()) {
            Some(KernelObject::PciDevice(device)) => device.set_interrupt_mode(mode),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

pub(crate) fn release_pci_device_resources(state: &KernelState, device: PciDeviceObject) {
    let mut registry = state.registry.lock();
    registry.release_kernel_ref(device.config_object);
    registry.release_kernel_ref(device.config_backing_object);
    registry.release_kernel_ref(device.bar0_object);
    registry.release_kernel_ref(device.bar0_backing_object);
    for key in device.ready_irqs {
        registry.release_kernel_ref(key);
    }
    for key in device.tx_irqs {
        registry.release_kernel_ref(key);
    }
    for key in device.rx_irqs {
        registry.release_kernel_ref(key);
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
