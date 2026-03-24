//! Kernel IRQ routing table.
//!
//! Maps interrupt vectors to bound kernel interrupt objects.  Hardware
//! ISR stubs call `handle_irq(vector)` which increments the pending
//! count on the bound object and signals it.

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::Mutex;

/// IRQ delivery mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IrqMode {
    /// Software-triggered virtual interrupt (existing model).
    Virtual,
    /// IOAPIC pin-routed hardware interrupt.
    IoApic { pin: u8 },
    /// MSI-delivered interrupt (future expansion).
    Msi { device_id: u32, msi_index: u8 },
}

/// One route entry in the IRQ table.
#[derive(Clone, Debug)]
pub(crate) struct IrqRoute {
    pub(crate) vector: u8,
    pub(crate) mode: IrqMode,
    /// Object key of the bound InterruptObject, if any.
    pub(crate) bound_object_id: Option<u64>,
}

/// Global IRQ routing table.
static IRQ_TABLE: Mutex<IrqTable> = Mutex::new(IrqTable::new());

struct IrqTable {
    routes: BTreeMap<u8, IrqRoute>,
    next_vector: u8,
}

impl IrqTable {
    const fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
            next_vector: 0x30, // vectors 0x30-0x4F reserved for device IRQs
        }
    }
}

/// Maximum device IRQ vector.
const MAX_DEVICE_VECTOR: u8 = 0x4F;

/// Allocate the next available IRQ vector and create a route entry.
pub(crate) fn alloc_vector(mode: IrqMode) -> Option<u8> {
    let mut table = IRQ_TABLE.lock();
    if table.next_vector > MAX_DEVICE_VECTOR {
        return None; // exhausted
    }
    let vector = table.next_vector;
    table.next_vector += 1;
    table.routes.insert(
        vector,
        IrqRoute {
            vector,
            mode,
            bound_object_id: None,
        },
    );
    Some(vector)
}

/// Bind an interrupt object to an allocated vector.
pub(crate) fn bind_object(vector: u8, object_id: u64) {
    let mut table = IRQ_TABLE.lock();
    if let Some(route) = table.routes.get_mut(&vector) {
        route.bound_object_id = Some(object_id);
    }
}

/// Unbind an interrupt object from a vector.
pub(crate) fn unbind_object(vector: u8) {
    let mut table = IRQ_TABLE.lock();
    if let Some(route) = table.routes.get_mut(&vector) {
        route.bound_object_id = None;
    }
}

/// Called from ISR stubs when a hardware interrupt fires.
/// Returns the bound object id if one exists, so the caller can
/// signal the interrupt object.
pub(crate) fn handle_irq(vector: u8) -> Option<u64> {
    let table = IRQ_TABLE.lock();
    table
        .routes
        .get(&vector)
        .and_then(|route| route.bound_object_id)
}

/// Query a route entry by vector.
pub(crate) fn get_route(vector: u8) -> Option<IrqRoute> {
    let table = IRQ_TABLE.lock();
    table.routes.get(&vector).cloned()
}
