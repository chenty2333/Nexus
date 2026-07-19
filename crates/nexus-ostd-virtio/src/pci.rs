// SPDX-License-Identifier: MPL-2.0

//! Private PCI configuration, BAR-ownership, and MMIO-claim substrate.

use alloc::sync::Arc;
use core::{
    fmt,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use ostd::{
    arch::device::io_port::ReadWriteAccess,
    io::{IoMem, IoPort},
    sync::SpinLock,
};
use virtio_drivers::{
    PhysAddr,
    transport::{
        DeviceType,
        pci::{
            bus::{BarInfo, Command, ConfigurationAccess, DeviceFunction, PciRoot},
            virtio_device_type,
        },
    },
};

const CONFIG_ADDRESS: u16 = 0x0cf8;
const CONFIG_DATA: u16 = 0x0cfc;
const EXPECTED_DEVICE: DeviceFunction = DeviceFunction {
    bus: 0,
    device: 5,
    function: 0,
};
const MODERN_VIRTIO_BLOCK_DEVICE_ID: u16 = 0x1042;
const INTERRUPT_CONFIG_OFFSET: u8 = 0x3c;
const INTX_NOT_CONNECTED: u8 = 0xff;
const EXPECTED_INTX_PIN: u8 = 1;

static NEXT_INTX_OWNER_ID: AtomicU64 = AtomicU64::new(1);

struct ConfigPorts {
    address: IoPort<u32, ReadWriteAccess>,
    data: IoPort<u32, ReadWriteAccess>,
}

/// Serialized PCI configuration mechanism #1 access.
#[derive(Clone)]
pub(crate) struct PioConfigurationAccess {
    ports: Arc<SpinLock<ConfigPorts>>,
}

impl PioConfigurationAccess {
    fn acquire() -> Result<Self, PciDiscoveryError> {
        let address = IoPort::acquire(CONFIG_ADDRESS)
            .map_err(|_| PciDiscoveryError::ConfigurationAddressBusy)?;
        let data =
            IoPort::acquire(CONFIG_DATA).map_err(|_| PciDiscoveryError::ConfigurationDataBusy)?;
        Ok(Self {
            ports: Arc::new(SpinLock::new(ConfigPorts { address, data })),
        })
    }
}

fn config_address(device_function: DeviceFunction, register_offset: u8) -> u32 {
    assert!(device_function.valid());
    assert_eq!(
        register_offset & 0x03,
        0,
        "PCI config access is word aligned"
    );

    0x8000_0000
        | (u32::from(device_function.bus) << 16)
        | (u32::from(device_function.device) << 11)
        | (u32::from(device_function.function) << 8)
        | u32::from(register_offset)
}

impl ConfigurationAccess for PioConfigurationAccess {
    fn read_word(&self, device_function: DeviceFunction, register_offset: u8) -> u32 {
        let ports = self.ports.lock();
        ports
            .address
            .write(config_address(device_function, register_offset));
        ports.data.read()
    }

    fn write_word(&mut self, device_function: DeviceFunction, register_offset: u8, data: u32) {
        let ports = self.ports.lock();
        ports
            .address
            .write(config_address(device_function, register_offset));
        ports.data.write(data);
    }

    unsafe fn unsafe_clone(&self) -> Self {
        Self {
            ports: self.ports.clone(),
        }
    }
}

pub(crate) type RawRoot = PciRoot<PioConfigurationAccess>;

/// Copyable descriptive identity, never an ownership or MMIO capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceBdf {
    bus: u8,
    device: u8,
    function: u8,
}

/// Typed failure while discovering and exclusively owning the production PCI fixture.
///
/// Discovery is transactional: no BAR owner is installed in the global registry
/// unless every validation and acquisition below succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciDiscoveryError {
    /// Another owner already holds the PCI configuration-address port.
    ConfigurationAddressBusy,
    /// Another owner already holds the PCI configuration-data port.
    ConfigurationDataBusy,
    /// More than one modern VirtIO block function was enumerated on bus zero.
    MultipleBlockDevices,
    /// No modern VirtIO block function was enumerated on bus zero.
    MissingBlockDevice,
    /// The discovered block function is not the bounded production fixture.
    UnexpectedBlockDeviceBdf { observed: DeviceBdf },
    /// The discovered function does not advertise the VirtIO vendor ID.
    UnexpectedVendor { observed: u16 },
    /// The discovered function is not the modern VirtIO block device ID.
    UnexpectedDeviceId { observed: u16 },
    /// PCI BAR discovery failed for the owned function.
    BarsUnavailable,
    /// A previous root still owns the process-wide BAR registry.
    BarOwnersAlreadyInstalled,
    /// A memory BAR has no firmware-assigned address.
    BarAddressMissing { index: u8 },
    /// A memory BAR advertises an empty range.
    BarSizeZero { index: u8 },
    /// A memory BAR address cannot be represented by this kernel.
    BarAddressOutOfRange { index: u8 },
    /// A memory BAR length cannot be represented by this kernel.
    BarSizeOutOfRange { index: u8 },
    /// A memory BAR range wraps the kernel address space.
    BarRangeOverflow { index: u8 },
    /// Another kernel owner already retains the advertised BAR range.
    BarOwnerUnavailable { index: u8 },
    /// The function contains no usable memory BAR.
    NoMemoryBars,
    /// The non-zero INTx owner namespace is exhausted.
    IntxOwnerIdentityExhausted,
}

/// Descriptive PCI INTx routing coordinates for the fixed Nexus block fixture.
///
/// The route is read from the standard PCI interrupt line/pin register at
/// configuration offset `0x3c`. It is not an IRQ-controller capability and
/// cannot install a handler by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntxRoute {
    device_bdf: DeviceBdf,
    line: u8,
    pin: u8,
}

impl IntxRoute {
    /// Returns the exact PCI function which advertised this route.
    pub const fn device_bdf(self) -> DeviceBdf {
        self.device_bdf
    }

    /// Returns the firmware-programmed legacy interrupt line.
    pub const fn line(self) -> u8 {
        self.line
    }

    /// Returns the PCI interrupt pin number (`1` is INTA#).
    pub const fn pin(self) -> u8 {
        self.pin
    }
}

/// Linear proof that one claimed INTx owner is in the masked state.
///
/// Private owner/epoch fields prevent downstream code from manufacturing or
/// replaying a token for a foreign [`Root`]. The token is intentionally neither
/// `Clone` nor `Copy`.
#[must_use = "retain the masked token until INTx is deliberately unmasked"]
pub struct MaskedIntx {
    owner_id: u64,
    epoch: u64,
    route: IntxRoute,
}

impl MaskedIntx {
    /// Returns the descriptive route without duplicating this state token.
    pub const fn route(&self) -> IntxRoute {
        self.route
    }
}

/// Linear proof that one claimed INTx owner is in the unmasked state.
#[must_use = "mask INTx again before dismantling interrupt ownership"]
pub struct UnmaskedIntx {
    owner_id: u64,
    epoch: u64,
    route: IntxRoute,
}

impl UnmaskedIntx {
    /// Returns the descriptive route without consuming the state token.
    pub const fn route(&self) -> IntxRoute {
        self.route
    }
}

/// Rejection from claiming or transitioning an INTx owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntxTransitionError {
    /// This root already issued its unique initial masked token.
    AlreadyClaimed,
    /// The fixed fixture has no usable firmware-programmed INTx route.
    InvalidRoute,
    /// The token belongs to another root or route.
    ForeignOwner,
    /// The root is not in the state consumed by this transition.
    WrongState,
    /// The token names an earlier transition epoch.
    StaleEpoch,
    /// No further transition epoch can be represented without aliasing an old token.
    EpochExhausted,
    /// PCI command observation did not support the requested transition.
    CommandReadbackMismatch {
        /// Requested state of `Command::INTERRUPT_DISABLE`.
        expected_masked: bool,
        /// State observed at a failed precondition or after the command write.
        observed_masked: bool,
        /// A command write changed a bit other than `INTERRUPT_DISABLE`.
        other_bits_changed: bool,
        /// Exact restoration failed and the root entered a poisoned state.
        poisoned: bool,
    },
}

/// A failed transition which returns the original linear input token.
///
/// When [`IntxTransitionError::CommandReadbackMismatch`] reports
/// `poisoned: true`, the returned token is retained only as evidence and is no
/// longer accepted; use [`Root::recover_masked_intx_fail_closed`] to invalidate
/// it and converge to a new masked epoch.
#[must_use = "inspect the error and retry or retain the returned INTx token"]
pub struct IntxTransitionFailure<T> {
    error: IntxTransitionError,
    token: T,
}

impl<T> IntxTransitionFailure<T> {
    /// Returns the exact owner/state validation error.
    pub const fn error(&self) -> IntxTransitionError {
        self.error
    }

    /// Borrows the unchanged input token.
    pub const fn token(&self) -> &T {
        &self.token
    }

    /// Recovers the unchanged linear token for the correct owner or epoch.
    pub fn into_token(self) -> T {
        self.token
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntxOwnershipState {
    Unclaimed,
    Masked { epoch: u64 },
    Unmasked { epoch: u64 },
    Poisoned { epoch: u64, observed_masked: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedIntxState {
    Masked,
    Unmasked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IntxCommandObservation {
    before: Command,
    expected: Command,
    observed: Command,
}

impl IntxCommandObservation {
    fn is_exact(self) -> bool {
        self.observed == self.expected
    }

    fn observed_masked(self) -> bool {
        self.observed.contains(Command::INTERRUPT_DISABLE)
    }

    fn other_bits_changed(self) -> bool {
        self.observed.difference(Command::INTERRUPT_DISABLE)
            != self.before.difference(Command::INTERRUPT_DISABLE)
    }

    fn error(self, expected_masked: bool, poisoned: bool) -> IntxTransitionError {
        IntxTransitionError::CommandReadbackMismatch {
            expected_masked,
            observed_masked: self.observed_masked(),
            other_bits_changed: self.other_bits_changed(),
            poisoned,
        }
    }
}

const fn decode_intx_route(device_bdf: DeviceBdf, interrupt_config: u32) -> IntxRoute {
    IntxRoute {
        device_bdf,
        line: interrupt_config as u8,
        pin: (interrupt_config >> 8) as u8,
    }
}

const fn command_with_intx_mask(command: Command, masked: bool) -> Command {
    if masked {
        command.union(Command::INTERRUPT_DISABLE)
    } else {
        command.difference(Command::INTERRUPT_DISABLE)
    }
}

fn allocate_intx_owner_id() -> Result<u64, PciDiscoveryError> {
    NEXT_INTX_OWNER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| PciDiscoveryError::IntxOwnerIdentityExhausted)
}

fn next_intx_epoch(epoch: u64) -> Result<u64, IntxTransitionError> {
    epoch
        .checked_add(1)
        .ok_or(IntxTransitionError::EpochExhausted)
}

impl DeviceBdf {
    /// Constructs descriptive PCI coordinates without claiming hardware.
    pub const fn from_coordinates(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    pub const fn bus(self) -> u8 {
        self.bus
    }

    pub const fn device(self) -> u8 {
        self.device
    }

    pub const fn function(self) -> u8 {
        self.function
    }
}

impl From<DeviceFunction> for DeviceBdf {
    fn from(value: DeviceFunction) -> Self {
        Self {
            bus: value.bus,
            device: value.device,
            function: value.function,
        }
    }
}

impl fmt::Display for DeviceBdf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}.{}",
            self.bus, self.device, self.function
        )
    }
}

/// Opaque, non-copyable owner of the PCI configuration root and the one
/// discovered VirtIO block function.
///
/// The raw `PciRoot<PioConfigurationAccess>` is deliberately private: callers
/// can neither clone the configuration accessor nor manufacture an MMIO
/// capability outside the facade lifecycle.
pub struct Root {
    inner: RawRoot,
    device_function: DeviceFunction,
    memory_bars: usize,
    intx_route: IntxRoute,
    intx_owner_id: u64,
    intx_state: IntxOwnershipState,
    portal_claimed: bool,
}

impl Root {
    pub const fn device_bdf(&self) -> DeviceBdf {
        DeviceBdf {
            bus: self.device_function.bus,
            device: self.device_function.device,
            function: self.device_function.function,
        }
    }

    pub const fn memory_bar_count(&self) -> usize {
        self.memory_bars
    }

    /// Returns the fixed fixture's route read from PCI configuration `0x3c`.
    ///
    /// This copyable value is descriptive only. It cannot claim, mask, or
    /// unmask INTx; only the root's linear owner-state methods can do so.
    pub const fn intx_route(&self) -> IntxRoute {
        self.intx_route
    }

    /// Claims the root's unique INTx lifecycle in the masked state.
    ///
    /// This method succeeds at most once for a root. It validates the fixed
    /// route, masks the function with complete command readback, installs the
    /// first owner epoch, and returns the only token which can be unmasked.
    pub fn claim_masked_intx(&mut self) -> Result<MaskedIntx, IntxTransitionError> {
        if self.intx_state != IntxOwnershipState::Unclaimed {
            return Err(IntxTransitionError::AlreadyClaimed);
        }
        if !self.has_valid_intx_route() {
            return Err(IntxTransitionError::InvalidRoute);
        }
        let epoch = 1;
        let observation = set_intx_mask(self, true);
        if !observation.is_exact() {
            self.intx_state = IntxOwnershipState::Poisoned {
                epoch,
                observed_masked: observation.observed_masked(),
            };
            return Err(observation.error(true, true));
        }
        self.intx_state = IntxOwnershipState::Masked { epoch };
        Ok(MaskedIntx {
            owner_id: self.intx_owner_id,
            epoch,
            route: self.intx_route,
        })
    }

    /// Unmasks legacy INTx by consuming the current masked owner epoch.
    ///
    /// Foreign, wrong-state, and stale tokens are rejected before hardware is
    /// touched and returned unchanged. If hardware was unexpectedly already
    /// unmasked, the facade masks it again before returning an error.
    pub fn unmask_intx(
        &mut self,
        masked: MaskedIntx,
    ) -> Result<UnmaskedIntx, IntxTransitionFailure<MaskedIntx>> {
        if let Err(error) = self.validate_intx_token(
            masked.owner_id,
            masked.epoch,
            masked.route,
            ExpectedIntxState::Masked,
        ) {
            return Err(IntxTransitionFailure {
                error,
                token: masked,
            });
        }
        let epoch = match next_intx_epoch(masked.epoch) {
            Ok(epoch) => epoch,
            Err(error) => {
                return Err(IntxTransitionFailure {
                    error,
                    token: masked,
                });
            }
        };
        let (_, observed_before_unmask) = self.inner.get_status_command(self.device_function);
        if !observed_before_unmask.contains(Command::INTERRUPT_DISABLE) {
            let recovery = set_intx_mask(self, true);
            if !recovery.is_exact() {
                self.intx_state = IntxOwnershipState::Poisoned {
                    epoch: masked.epoch,
                    observed_masked: recovery.observed_masked(),
                };
                return Err(IntxTransitionFailure {
                    error: recovery.error(true, true),
                    token: masked,
                });
            }
            return Err(IntxTransitionFailure {
                error: IntxTransitionError::CommandReadbackMismatch {
                    expected_masked: true,
                    observed_masked: false,
                    other_bits_changed: false,
                    poisoned: false,
                },
                token: masked,
            });
        }
        let observation = set_intx_mask(self, false);
        if !observation.is_exact() {
            let restored = restore_intx_command(self, observation.before);
            let poisoned = restored != observation.before;
            if poisoned {
                self.intx_state = IntxOwnershipState::Poisoned {
                    epoch: masked.epoch,
                    observed_masked: restored.contains(Command::INTERRUPT_DISABLE),
                };
            }
            return Err(IntxTransitionFailure {
                error: observation.error(false, poisoned),
                token: masked,
            });
        }
        self.intx_state = IntxOwnershipState::Unmasked { epoch };
        Ok(UnmaskedIntx {
            owner_id: self.intx_owner_id,
            epoch,
            route: self.intx_route,
        })
    }

    /// Masks legacy INTx by consuming the current unmasked owner epoch.
    ///
    /// Foreign, wrong-state, and stale tokens are rejected before hardware is
    /// touched and returned unchanged. A matching token always converges the
    /// hardware and root state to masked, including recovery when hardware was
    /// already fail-closed.
    pub fn mask_intx(
        &mut self,
        unmasked: UnmaskedIntx,
    ) -> Result<MaskedIntx, IntxTransitionFailure<UnmaskedIntx>> {
        if let Err(error) = self.validate_intx_token(
            unmasked.owner_id,
            unmasked.epoch,
            unmasked.route,
            ExpectedIntxState::Unmasked,
        ) {
            return Err(IntxTransitionFailure {
                error,
                token: unmasked,
            });
        }

        let epoch = match next_intx_epoch(unmasked.epoch) {
            Ok(epoch) => epoch,
            Err(error) => {
                return Err(IntxTransitionFailure {
                    error,
                    token: unmasked,
                });
            }
        };
        let observation = set_intx_mask(self, true);
        if !observation.is_exact() {
            let restored = restore_intx_command(self, observation.before);
            let poisoned = restored != observation.before;
            if poisoned {
                self.intx_state = IntxOwnershipState::Poisoned {
                    epoch: unmasked.epoch,
                    observed_masked: restored.contains(Command::INTERRUPT_DISABLE),
                };
            }
            return Err(IntxTransitionFailure {
                error: observation.error(true, poisoned),
                token: unmasked,
            });
        }
        self.intx_state = IntxOwnershipState::Masked { epoch };
        Ok(MaskedIntx {
            owner_id: self.intx_owner_id,
            epoch,
            route: self.intx_route,
        })
    }

    /// Converges any previously claimed INTx lifecycle to a new masked epoch.
    ///
    /// This is the one-way fail-closed recovery path for a dropped token,
    /// teardown uncertainty, or poisoned command readback. It can never unmask
    /// INTx. A successful call invalidates every older masked or unmasked token
    /// and returns the only token for the new masked epoch.
    pub fn recover_masked_intx_fail_closed(&mut self) -> Result<MaskedIntx, IntxTransitionError> {
        let current_epoch = match self.intx_state {
            IntxOwnershipState::Unclaimed => return Err(IntxTransitionError::WrongState),
            IntxOwnershipState::Masked { epoch }
            | IntxOwnershipState::Unmasked { epoch }
            | IntxOwnershipState::Poisoned { epoch, .. } => epoch,
        };
        let epoch = next_intx_epoch(current_epoch)?;
        let observation = set_intx_mask(self, true);
        if !observation.is_exact() {
            self.intx_state = IntxOwnershipState::Poisoned {
                epoch,
                observed_masked: observation.observed_masked(),
            };
            return Err(observation.error(true, true));
        }
        self.intx_state = IntxOwnershipState::Masked { epoch };
        Ok(MaskedIntx {
            owner_id: self.intx_owner_id,
            epoch,
            route: self.intx_route,
        })
    }

    pub(crate) const fn device_function(&self) -> DeviceFunction {
        self.device_function
    }

    pub(crate) fn claim_device_function(&mut self) -> DeviceFunction {
        assert!(!self.portal_claimed, "PCI device portal claimed twice");
        self.portal_claimed = true;
        self.device_function
    }

    /// Claims the device for a production owner without panicking on reuse.
    ///
    /// The caller holds `&mut Root`, so checking and installing the claim are
    /// one exclusive operation. The legacy portal keeps its older invariant-
    /// checked constructor; new production paths surface reuse as typed input
    /// failure.
    pub(crate) fn try_claim_device_function(&mut self) -> Option<DeviceFunction> {
        if self.portal_claimed {
            None
        } else {
            self.portal_claimed = true;
            Some(self.device_function)
        }
    }

    pub(crate) fn raw_mut(&mut self) -> &mut RawRoot {
        &mut self.inner
    }

    fn assert_device(&self, device_function: DeviceFunction) {
        assert_eq!(
            self.device_function, device_function,
            "foreign PCI root owner"
        );
    }

    const fn has_valid_intx_route(&self) -> bool {
        self.intx_route.line != INTX_NOT_CONNECTED && self.intx_route.pin == EXPECTED_INTX_PIN
    }

    fn validate_intx_token(
        &self,
        owner_id: u64,
        epoch: u64,
        route: IntxRoute,
        expected: ExpectedIntxState,
    ) -> Result<(), IntxTransitionError> {
        if owner_id != self.intx_owner_id || route != self.intx_route {
            return Err(IntxTransitionError::ForeignOwner);
        }
        let current_epoch = match (self.intx_state, expected) {
            (IntxOwnershipState::Masked { epoch }, ExpectedIntxState::Masked)
            | (IntxOwnershipState::Unmasked { epoch }, ExpectedIntxState::Unmasked) => epoch,
            _ => return Err(IntxTransitionError::WrongState),
        };
        if current_epoch != epoch {
            return Err(IntxTransitionError::StaleEpoch);
        }
        Ok(())
    }

    fn assert_intx_state_matches_readback(&self) {
        let (_, command) = self.inner.get_status_command(self.device_function);
        self.assert_intx_state_matches_command(command);
    }

    fn assert_intx_state_matches_command(&self, command: Command) {
        let masked = command.contains(Command::INTERRUPT_DISABLE);
        match self.intx_state {
            IntxOwnershipState::Unclaimed => {}
            IntxOwnershipState::Masked { .. } => {
                assert!(masked, "masked INTx owner disagrees with PCI command")
            }
            IntxOwnershipState::Unmasked { .. } => {
                assert!(!masked, "unmasked INTx owner disagrees with PCI command")
            }
            IntxOwnershipState::Poisoned {
                observed_masked, ..
            } => assert_eq!(
                masked, observed_masked,
                "poisoned INTx observation disagrees with PCI command"
            ),
        }
    }

    fn assert_internal_mask_allowed(&self) {
        assert!(
            matches!(
                self.intx_state,
                IntxOwnershipState::Unclaimed | IntxOwnershipState::Masked { .. }
            ),
            "recover or mask INTx through its linear owner-state API first"
        );
        self.assert_intx_state_matches_readback();
    }

    fn internal_mask_allowed_checked(&mut self) -> Result<(), PrepareCommandFailure> {
        match self.intx_state {
            IntxOwnershipState::Unclaimed => Ok(()),
            IntxOwnershipState::Masked { epoch } => {
                let (_, command) = self.inner.get_status_command(self.device_function);
                if command.contains(Command::INTERRUPT_DISABLE) {
                    Ok(())
                } else {
                    self.intx_state = IntxOwnershipState::Poisoned {
                        epoch,
                        observed_masked: false,
                    };
                    Err(PrepareCommandFailure::ReadbackMismatch {
                        original_command: command,
                    })
                }
            }
            IntxOwnershipState::Unmasked { .. } | IntxOwnershipState::Poisoned { .. } => {
                Err(PrepareCommandFailure::IntxStateUnavailable)
            }
        }
    }

    fn observe_internal_command_or_poison(&mut self, expected: Command, observed: Command) {
        if !self.observe_internal_command_checked(expected, observed) {
            panic!("PCI command readback mismatch");
        }
        self.assert_intx_state_matches_command(observed);
    }

    fn observe_internal_command_checked(&mut self, expected: Command, observed: Command) -> bool {
        let exact = observed == expected;
        if !exact
            && let IntxOwnershipState::Masked { epoch }
            | IntxOwnershipState::Unmasked { epoch }
            | IntxOwnershipState::Poisoned { epoch, .. } = self.intx_state
        {
            self.intx_state = IntxOwnershipState::Poisoned {
                epoch,
                observed_masked: observed.contains(Command::INTERRUPT_DISABLE),
            };
        }
        exact
    }
}

struct BarOwner {
    start: usize,
    end: usize,
    io_mem: IoMem,
}

struct BarRegistry {
    owners: [Option<BarOwner>; 6],
    installed: bool,
    transport_claims_active: bool,
    claims: [Option<MmioClaim>; 4],
}

#[derive(Clone, Copy)]
struct MmioClaim {
    start: usize,
    end: usize,
}

impl BarRegistry {
    const fn new() -> Self {
        Self {
            owners: [const { None }; 6],
            installed: false,
            transport_claims_active: false,
            claims: [const { None }; 4],
        }
    }
}

pub fn begin_transport_claims() {
    try_begin_transport_claims().expect("transport claim lifecycle is quiescent");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportClaimStartError {
    BarOwnersUnavailable,
    AlreadyActive,
    StaleClaims,
}

pub(crate) fn try_begin_transport_claims() -> Result<(), TransportClaimStartError> {
    let mut registry = BAR_REGISTRY.lock();
    if !registry.installed {
        return Err(TransportClaimStartError::BarOwnersUnavailable);
    }
    if registry.transport_claims_active {
        return Err(TransportClaimStartError::AlreadyActive);
    }
    if !registry.claims.iter().all(Option::is_none) {
        return Err(TransportClaimStartError::StaleClaims);
    }
    registry.transport_claims_active = true;
    Ok(())
}

/// Releases the raw capability subranges claimed by one destroyed transport.
///
/// # Safety
///
/// Every `PciTransport` and raw MMIO pointer for the transport generation must
/// already have been destroyed. A quarantined live transport must retain its
/// claims so a replacement cannot alias its capability mappings.
pub(crate) unsafe fn release_transport_claims() {
    let mut registry = BAR_REGISTRY.lock();
    assert!(registry.transport_claims_active);
    registry.claims.fill(None);
    registry.transport_claims_active = false;
}

/// Attempts to release the claims of a transport which never became exposed.
///
/// This is the production-constructor rollback counterpart of
/// [`release_transport_claims`]. It deliberately does not assert: an
/// inconsistent registry means rollback cannot be certified, so the static
/// claim state is retained and the caller must quarantine the preparation.
///
/// # Safety
///
/// Every `PciTransport` and raw MMIO pointer for the attempted transport must
/// already have been destroyed. This function is only valid before the device
/// reached `DRIVER_OK`.
pub(crate) unsafe fn release_unexposed_transport_claims_checked() -> bool {
    let mut registry = BAR_REGISTRY.lock();
    if !registry.installed || !registry.transport_claims_active {
        return false;
    }
    registry.claims.fill(None);
    registry.transport_claims_active = false;
    true
}

static BAR_REGISTRY: SpinLock<BarRegistry> = SpinLock::new(BarRegistry::new());

/// Read-only transport-capability projection for preparation evidence.
///
/// The range coordinates stay private. A caller can learn only whether the
/// unique transport lifecycle is active and how many owner-backed subranges
/// it currently retains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportClaimObservation {
    pub(crate) active: bool,
    pub(crate) claim_count: usize,
}

pub(crate) fn transport_claim_observation() -> TransportClaimObservation {
    let registry = BAR_REGISTRY.lock();
    TransportClaimObservation {
        active: registry.transport_claims_active,
        claim_count: registry.claims.iter().flatten().count(),
    }
}

/// Discovers exactly one modern VirtIO block device on bus 0 and installs one
/// owner for each of its memory BARs before raw capability pointers are made.
pub fn discover_and_own_bars() -> Result<Root, PciDiscoveryError> {
    let configuration = PioConfigurationAccess::acquire()?;
    let mut root = RawRoot::new(configuration.clone());
    let mut found = None;

    for (device_function, info) in root.enumerate_bus(0) {
        if virtio_device_type(&info) == Some(DeviceType::Block) {
            if found.is_some() {
                return Err(PciDiscoveryError::MultipleBlockDevices);
            }
            found = Some((device_function, info));
        }
    }

    let (device_function, info) = found.ok_or(PciDiscoveryError::MissingBlockDevice)?;
    if device_function != EXPECTED_DEVICE {
        return Err(PciDiscoveryError::UnexpectedBlockDeviceBdf {
            observed: DeviceBdf::from(device_function),
        });
    }
    if info.vendor_id != 0x1af4 {
        return Err(PciDiscoveryError::UnexpectedVendor {
            observed: info.vendor_id,
        });
    }
    if info.device_id != MODERN_VIRTIO_BLOCK_DEVICE_ID {
        return Err(PciDiscoveryError::UnexpectedDeviceId {
            observed: info.device_id,
        });
    }

    let bars = root
        .bars(device_function)
        .map_err(|_| PciDiscoveryError::BarsUnavailable)?;
    {
        let registry = BAR_REGISTRY.lock();
        if registry.installed
            || registry.transport_claims_active
            || !registry.owners.iter().all(Option::is_none)
            || !registry.claims.iter().all(Option::is_none)
        {
            return Err(PciDiscoveryError::BarOwnersAlreadyInstalled);
        }
    }
    let mut owners = [const { None }; 6];
    let mut memory_bars = 0;

    for (index, bar) in bars.into_iter().enumerate() {
        let Some(BarInfo::Memory { address, size, .. }) = bar else {
            continue;
        };
        let index = index as u8;
        if address == 0 {
            return Err(PciDiscoveryError::BarAddressMissing { index });
        }
        if size == 0 {
            return Err(PciDiscoveryError::BarSizeZero { index });
        }
        let start = usize::try_from(address)
            .map_err(|_| PciDiscoveryError::BarAddressOutOfRange { index })?;
        let length =
            usize::try_from(size).map_err(|_| PciDiscoveryError::BarSizeOutOfRange { index })?;
        let end = start
            .checked_add(length)
            .ok_or(PciDiscoveryError::BarRangeOverflow { index })?;
        let io_mem = IoMem::acquire(start..end)
            .map_err(|_| PciDiscoveryError::BarOwnerUnavailable { index })?;
        owners[usize::from(index)] = Some(BarOwner { start, end, io_mem });
        memory_bars += 1;
    }

    if memory_bars == 0 {
        return Err(PciDiscoveryError::NoMemoryBars);
    }
    let intx_route = decode_intx_route(
        DeviceBdf::from(device_function),
        configuration.read_word(device_function, INTERRUPT_CONFIG_OFFSET),
    );
    let intx_owner_id = allocate_intx_owner_id()?;
    let mut registry = BAR_REGISTRY.lock();
    if registry.installed
        || registry.transport_claims_active
        || !registry.owners.iter().all(Option::is_none)
        || !registry.claims.iter().all(Option::is_none)
    {
        return Err(PciDiscoveryError::BarOwnersAlreadyInstalled);
    }
    registry.owners = owners;
    registry.installed = true;
    drop(registry);
    Ok(Root {
        inner: root,
        device_function,
        memory_bars,
        intx_route,
        intx_owner_id,
        intx_state: IntxOwnershipState::Unclaimed,
        portal_claimed: false,
    })
}

fn set_intx_mask(root: &mut Root, masked: bool) -> IntxCommandObservation {
    let device_function = root.device_function;
    let (_, before) = root.inner.get_status_command(device_function);
    let expected = command_with_intx_mask(before, masked);
    root.inner.set_command(device_function, expected);
    let (_, observed) = root.inner.get_status_command(device_function);
    IntxCommandObservation {
        before,
        expected,
        observed,
    }
}

fn restore_intx_command(root: &mut Root, command: Command) -> Command {
    let device_function = root.device_function;
    root.inner.set_command(device_function, command);
    let (_, observed) = root.inner.get_status_command(device_function);
    observed
}

pub(crate) fn enable_device_for_prepare(
    root: &mut Root,
    device_function: DeviceFunction,
) -> Command {
    match enable_device_for_prepare_checked(root, device_function) {
        Ok(command) => command,
        Err(PrepareCommandFailure::ForeignRoot) => panic!("foreign PCI root owner"),
        Err(PrepareCommandFailure::IntxStateUnavailable) => {
            panic!("recover or mask INTx through its linear owner-state API first")
        }
        Err(PrepareCommandFailure::ReadbackMismatch { .. }) => {
            panic!("PCI command readback mismatch")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrepareCommandFailure {
    ForeignRoot,
    IntxStateUnavailable,
    ReadbackMismatch { original_command: Command },
}

pub(crate) fn enable_device_for_prepare_checked(
    root: &mut Root,
    device_function: DeviceFunction,
) -> Result<Command, PrepareCommandFailure> {
    if root.device_function != device_function {
        return Err(PrepareCommandFailure::ForeignRoot);
    }
    root.internal_mask_allowed_checked()?;
    let (_, command) = root.inner.get_status_command(device_function);
    let expected =
        command | Command::MEMORY_SPACE | Command::BUS_MASTER | Command::INTERRUPT_DISABLE;
    root.inner.set_command(device_function, expected);
    let (_, observed) = root.inner.get_status_command(device_function);
    if root.observe_internal_command_checked(expected, observed) {
        root.assert_intx_state_matches_command(observed);
        Ok(command)
    } else {
        Err(PrepareCommandFailure::ReadbackMismatch {
            original_command: command,
        })
    }
}

pub(crate) fn enable_device(root: &mut Root, device_function: DeviceFunction) {
    let _ = enable_device_for_prepare(root, device_function);
}

pub(crate) fn restore_device_command_checked(
    root: &mut Root,
    device_function: DeviceFunction,
    command: Command,
) -> bool {
    root.assert_device(device_function);
    root.inner.set_command(device_function, command);
    let (_, observed) = root.inner.get_status_command(device_function);
    root.observe_internal_command_checked(command, observed)
}

pub(crate) fn disable_bus_master(root: &mut Root, device_function: DeviceFunction) {
    root.assert_device(device_function);
    root.assert_internal_mask_allowed();
    let (_, command) = root.inner.get_status_command(device_function);
    let expected = (command & !Command::BUS_MASTER) | Command::INTERRUPT_DISABLE;
    root.inner.set_command(device_function, expected);
    let (_, observed) = root.inner.get_status_command(device_function);
    root.observe_internal_command_or_poison(expected, observed);
}

pub(crate) fn disable_bus_master_checked(
    root: &mut Root,
    device_function: DeviceFunction,
) -> Result<(), PrepareCommandFailure> {
    if root.device_function != device_function {
        return Err(PrepareCommandFailure::ForeignRoot);
    }
    root.internal_mask_allowed_checked()?;
    let (_, command) = root.inner.get_status_command(device_function);
    let expected = (command & !Command::BUS_MASTER) | Command::INTERRUPT_DISABLE;
    root.inner.set_command(device_function, expected);
    let (_, observed) = root.inner.get_status_command(device_function);
    if root.observe_internal_command_checked(expected, observed) {
        root.assert_intx_state_matches_command(observed);
        Ok(())
    } else {
        Err(PrepareCommandFailure::ReadbackMismatch {
            original_command: command,
        })
    }
}

/// Returns a BAR-subrange pointer while the registry retains the unique
/// `IoMem` owner. The VirtIO HAL is the only caller and never accesses the
/// same range through `IoMem` while a transport exists.
pub(crate) unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
    let start = usize::try_from(paddr).expect("MMIO address fits usize");
    let end = start.checked_add(size).expect("MMIO range overflow");
    let mut registry = BAR_REGISTRY.lock();
    assert!(
        registry.transport_claims_active,
        "MMIO pointer requested outside a retained transport lifecycle"
    );

    for claim in registry.claims.iter().flatten() {
        assert!(
            end <= claim.start || claim.end <= start,
            "overlapping VirtIO MMIO capability claims"
        );
    }
    let claim_slot = registry
        .claims
        .iter_mut()
        .find(|claim| claim.is_none())
        .expect("unexpected number of VirtIO MMIO capability ranges");
    *claim_slot = Some(MmioClaim { start, end });

    for owner in registry.owners.iter().flatten() {
        if owner.start <= start && end <= owner.end {
            // SAFETY: `owner` remains installed for the lifetime of every PCI
            // transport. The caller upholds the no-alias MMIO access contract.
            let base = unsafe { owner.io_mem.as_non_null_ptr() };
            let offset = start - owner.start;
            // SAFETY: containment above proves `offset..offset + size` lies in
            // the owner-bound MMIO mapping.
            return unsafe { NonNull::new_unchecked(base.as_ptr().add(offset)) };
        }
    }

    panic!("VirtIO requested MMIO outside retained BAR owners");
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("pci.rs");

    #[test]
    fn interrupt_config_word_decodes_line_and_pin_bytes() {
        let bdf = DeviceBdf::from_coordinates(0, 5, 0);
        let route = decode_intx_route(bdf, 0xa5_5a_02_0b);
        assert_eq!(route.device_bdf(), bdf);
        assert_eq!(route.line(), 0x0b);
        assert_eq!(route.pin(), 0x02);
    }

    #[test]
    fn intx_command_transition_changes_only_interrupt_disable() {
        let original = Command::MEMORY_SPACE
            | Command::BUS_MASTER
            | Command::PARITY_ERROR_RESPONSE
            | Command::SERR_ENABLE;
        let masked = command_with_intx_mask(original, true);
        assert!(masked.contains(Command::INTERRUPT_DISABLE));
        assert_eq!(masked.difference(Command::INTERRUPT_DISABLE), original);

        let unmasked = command_with_intx_mask(masked, false);
        assert!(!unmasked.contains(Command::INTERRUPT_DISABLE));
        assert_eq!(unmasked, original);

        let exact = IntxCommandObservation {
            before: original,
            expected: masked,
            observed: masked,
        };
        assert!(exact.is_exact());
        assert!(!exact.other_bits_changed());
        let collateral = IntxCommandObservation {
            before: original,
            expected: masked,
            observed: masked | Command::IO_SPACE,
        };
        assert!(!collateral.is_exact());
        assert!(collateral.other_bits_changed());
    }

    #[test]
    fn intx_masking_api_preserves_owner_checked_typestate_shape() {
        let implementation = SOURCE
            .split_once("#[cfg(test)]")
            .expect("test module follows implementation")
            .0;
        assert!(implementation.contains(
            "pub struct MaskedIntx {\n    owner_id: u64,\n    epoch: u64,\n    route: IntxRoute,"
        ));
        assert!(implementation.contains(
            "pub struct UnmaskedIntx {\n    owner_id: u64,\n    epoch: u64,\n    route: IntxRoute,"
        ));
        assert!(implementation.contains(
            "pub fn claim_masked_intx(&mut self) -> Result<MaskedIntx, IntxTransitionError>"
        ));
        assert!(implementation.contains("pub fn unmask_intx("));
        assert!(implementation.contains("masked: MaskedIntx,"));
        assert!(implementation.contains("IntxTransitionFailure<MaskedIntx>"));
        assert!(implementation.contains("pub fn mask_intx("));
        assert!(implementation.contains("unmasked: UnmaskedIntx,"));
        assert!(implementation.contains("IntxTransitionFailure<UnmaskedIntx>"));
        assert!(implementation.contains("intx_state: IntxOwnershipState,"));
        assert!(implementation.contains("Poisoned { epoch: u64, observed_masked: bool }"));
        assert!(implementation.contains("pub fn recover_masked_intx_fail_closed("));
        assert!(implementation.contains("IntxCommandObservation"));
        assert!(implementation.contains("self.validate_intx_token("));
        assert!(implementation.contains("return Err(IntxTransitionFailure {"));
        assert!(implementation.contains("let (_, observed) = root.inner.get_status_command"));
        assert!(!implementation.contains("pub fn mask_intx(&mut self, route: IntxRoute)"));
        assert!(!implementation.contains("#[derive(Clone, Copy)]\npub struct MaskedIntx"));
        assert!(!implementation.contains("#[derive(Clone, Copy)]\npub struct UnmaskedIntx"));

        let unmask_epoch = implementation
            .find("let epoch = match next_intx_epoch(masked.epoch)")
            .unwrap();
        let unmask_write = implementation.find("set_intx_mask(self, false);").unwrap();
        assert!(unmask_epoch < unmask_write);
        let mask_epoch = implementation
            .find("let epoch = match next_intx_epoch(unmasked.epoch)")
            .unwrap();
        let mask_write = implementation.rfind("set_intx_mask(self, true);").unwrap();
        assert!(mask_epoch < mask_write);
    }
}
