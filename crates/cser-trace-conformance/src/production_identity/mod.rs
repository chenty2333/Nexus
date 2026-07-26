//! The `ProductionIdentityCser` specification family.
//!
//! Unlike the baseline family, this specification already releases its own
//! reachability witnesses, and `specs/cser/check.sh` already runs them. This
//! lane replays exactly those released witnesses under the released safety
//! configuration, so the behaviors it checks are the repository's own
//! published coverage claims rather than ones this crate invented.

pub mod actions;
pub mod replay;

use crate::tlc::{FamilySpec, Witness};

/// Released reachability witnesses replayed for this family.
///
/// Every entry names an invariant defined in `ProductionIdentityCser.tla`
/// together with the scenario constraint `check.sh` pairs it with. Because
/// `definition` is `None`, TLC runs the released module and configuration
/// unmodified apart from the appended `INVARIANT` and `CONSTRAINT` lines.
pub const WITNESSES: &[Witness] = &[
    Witness {
        invariant: "IdentityPreservingReadAbsent",
        definition: None,
        constraint: Some("NormalWitnessScenario"),
        description: "workload-created identities survive one same-effect block read and \
                      root closure",
    },
    Witness {
        invariant: "FilesystemCrashAdoptAbsent",
        definition: None,
        constraint: Some("CrashWitnessScenario"),
        description: "filesystem crash/rebind/adopt changes only the current domain binding",
    },
    Witness {
        invariant: "CommitWinsRevokeRaceAbsent",
        definition: None,
        constraint: Some("CommitRaceWitnessScenario"),
        description: "device batch commit wins the shared root gate before revocation",
    },
    Witness {
        invariant: "RevokeWinsCommitRaceAbsent",
        definition: None,
        constraint: Some("CommitRaceWitnessScenario"),
        description: "root revocation wins the shared gate and aborts every uncommitted \
                      descendant",
    },
    Witness {
        invariant: "ResetIotlbSameEffectAbsent",
        definition: None,
        constraint: Some("TimeoutWitnessScenario"),
        description: "reset and IOTLB timeouts retain the same effect through retry and closure",
    },
    Witness {
        invariant: "CrossRegistryGenerationRejectAbsent",
        definition: None,
        constraint: Some("RejectWitnessScenario"),
        description: "foreign-registry and stale-device-generation inputs reject without \
                      semantic mutation",
    },
    Witness {
        invariant: "ActorSeparationAbsent",
        definition: None,
        constraint: Some("ActorWitnessScenario"),
        description: "abstract service/kernel/IRQ roles retain one identity chain",
    },
];

/// The family descriptor used to drive TLC.
pub const FAMILY: FamilySpec = FamilySpec {
    module: "ProductionIdentityCser",
    base_config: "ProductionIdentityCserSafetyMC.cfg",
    witnesses: WITNESSES,
};
