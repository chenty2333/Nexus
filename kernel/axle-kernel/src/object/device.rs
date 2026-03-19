use super::*;
use axle_types::pci::{
    AX_PCI_INTERRUPT_GROUP_READY, AX_PCI_INTERRUPT_GROUP_RX_COMPLETE,
    AX_PCI_INTERRUPT_GROUP_TX_KICK, ax_pci_bar_info_t, ax_pci_device_info_t,
    ax_pci_interrupt_info_t,
};
use axle_types::status::{ZX_ERR_BAD_HANDLE, ZX_ERR_OUT_OF_RANGE, ZX_ERR_WRONG_TYPE};

pub(crate) const BOOTSTRAP_NET_QUEUE_PAIR_COUNT: usize = 2;
pub(crate) const BOOTSTRAP_NET_QUEUE_SIZE: u32 = 4;
pub(crate) const BOOTSTRAP_NET_BAR_COUNT: u32 = 1;
pub(crate) const BOOTSTRAP_NET_INTERRUPT_GROUPS: u32 = 3;
pub(crate) const BOOTSTRAP_NET_BAR0_BYTES: u64 = crate::userspace::USER_PAGE_BYTES;
pub(crate) const BOOTSTRAP_NET_VENDOR_ID: u16 = 0x4158;
pub(crate) const BOOTSTRAP_NET_DEVICE_ID: u16 = 0x0001;
pub(crate) const BOOTSTRAP_NET_CLASS_CODE: u8 = 0x02;
pub(crate) const BOOTSTRAP_NET_SUBCLASS_ETHERNET: u8 = 0x00;
pub(crate) const BOOTSTRAP_NET_DEVICE_FEATURES: u32 = 1 << 0;

#[derive(Debug)]
pub(crate) struct PciDeviceObject {
    pub(crate) vendor_id: u16,
    pub(crate) device_id: u16,
    pub(crate) prog_if: u8,
    pub(crate) subclass: u8,
    pub(crate) class_code: u8,
    pub(crate) revision_id: u8,
    pub(crate) bar0_object: ObjectKey,
    pub(crate) bar0_backing_object: ObjectKey,
    pub(crate) bar0_size: u64,
    pub(crate) device_features: u32,
    pub(crate) queue_pairs: u32,
    pub(crate) queue_size: u32,
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

    fn bar(&self, bar_index: u32) -> Result<(ObjectKey, ax_pci_bar_info_t), zx_status_t> {
        if bar_index != 0 {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        Ok((
            self.bar0_object,
            ax_pci_bar_info_t {
                handle: ZX_HANDLE_INVALID,
                size: self.bar0_size,
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
    let bar0_object = create_global_vmo_object(
        state,
        process_id,
        axle_mm::VmoKind::Physical,
        |vm, global_vmo_id| {
            vm.create_physical_vmo_global(bar0_paddr, BOOTSTRAP_NET_BAR0_BYTES, global_vmo_id)
        },
    )?;

    let ready_irqs = create_interrupt_array(state)?;
    let tx_irqs = create_interrupt_array(state)?;
    let rx_irqs = create_interrupt_array(state)?;

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
                bar0_object,
                bar0_backing_object,
                bar0_size: BOOTSTRAP_NET_BAR0_BYTES,
                device_features: BOOTSTRAP_NET_DEVICE_FEATURES,
                queue_pairs: BOOTSTRAP_NET_QUEUE_PAIR_COUNT as u32,
                queue_size: BOOTSTRAP_NET_QUEUE_SIZE,
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
        let irq_object =
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::PciDevice(device)) => device.interrupt_key(group, queue_pair),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;
        let irq_handle =
            state.alloc_handle_for_object(irq_object, handle::interrupt_default_rights())?;
        Ok(ax_pci_interrupt_info_t { handle: irq_handle })
    })
}

pub(crate) fn release_pci_device_resources(state: &KernelState, device: PciDeviceObject) {
    let mut registry = state.registry.lock();
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
) -> Result<[ObjectKey; BOOTSTRAP_NET_QUEUE_PAIR_COUNT], zx_status_t> {
    let mut keys = [ObjectKey::INVALID; BOOTSTRAP_NET_QUEUE_PAIR_COUNT];
    for key in &mut keys {
        *key = create_interrupt_object(state)?;
    }
    Ok(keys)
}

fn create_interrupt_object(state: &KernelState) -> Result<ObjectKey, zx_status_t> {
    let object_id = state.alloc_object_id();
    state.with_registry_mut(|registry| {
        registry.insert(
            object_id,
            KernelObject::Interrupt(InterruptObject::new(true)),
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
