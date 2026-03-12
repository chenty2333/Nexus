#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Reference model and crash-check scaffolding for the first DataFS design cut.
//!
//! This crate is intentionally host-side and correctness-oriented. It does not
//! implement a production filesystem. Instead it carries:
//! - one small inode/object reference model
//! - logical journal records and replay
//! - invariant checking suitable for a future minimal fsck
//! - crash/fault injection hooks
//! - recovery/session metadata reserved for reconnect work

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// Stable inode/object id used by the reference model.
pub type ObjectId = u64;
/// Stable session id reserved for reconnect/rebind.
pub type SessionId = u64;
/// Stable open-file-description id reserved for reconnect/rebind.
pub type OpenFileDescriptionId = u64;

const ROOT_ID: ObjectId = 1;

/// Transport flavor reserved by the FS service contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportKind {
    /// Channel RPC in the first implementation.
    ChannelRpc,
    /// Future per-core shared ring transport.
    SharedRing,
}

/// Small trait that captures the transport/recovery surface the FS protocol must preserve.
pub trait FsTransportContract {
    /// Transport flavor in use.
    fn transport_kind(&self) -> TransportKind;
    /// Stable session identifier.
    fn session_id(&self) -> SessionId;
    /// Stable open-file-description identifier.
    fn open_file_description_id(&self) -> OpenFileDescriptionId;
    /// Whether reconnect/rebind is expected to work for this session.
    fn reconnectable(&self) -> bool;
}

/// Recovery metadata intentionally reserved before the real DataFS exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryHandle {
    /// Stable session identifier.
    pub session_id: SessionId,
    /// Stable open-file-description identifier.
    pub open_file_description_id: OpenFileDescriptionId,
    /// Whether reconnect/rebind is expected to work.
    pub reconnectable: bool,
    /// Wire transport family.
    pub transport: TransportKind,
}

impl FsTransportContract for RecoveryHandle {
    fn transport_kind(&self) -> TransportKind {
        self.transport
    }

    fn session_id(&self) -> SessionId {
        self.session_id
    }

    fn open_file_description_id(&self) -> OpenFileDescriptionId {
        self.open_file_description_id
    }

    fn reconnectable(&self) -> bool {
        self.reconnectable
    }
}

/// Frozen DataFS v1 constraints for the reference model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFsV1Contract {
    /// Filesystem lives in userspace.
    pub userspace_service: bool,
    /// Only one logical volume is modeled.
    pub single_volume: bool,
    /// Files use 64-bit object ids.
    pub object_ids_are_64_bit: bool,
    /// Regular-file data layout uses extents.
    pub extent_layout: bool,
    /// Directories use one indexed structure rather than flat scans.
    pub directory_index: bool,
    /// Metadata journal is logical rather than physical.
    pub logical_metadata_journal: bool,
    /// Journal/checkpoint records carry checksums.
    pub journal_checksum: bool,
    /// Checkpoints exist and bound replay.
    pub checkpoint: bool,
    /// Minimal fsck/invariant checker is part of the design.
    pub minimal_fsck: bool,
    /// Files may expose read-only `GetVmo`.
    pub read_only_get_vmo: bool,
    /// Writable mmap stays out of v1.
    pub writable_mmap_v1: bool,
    /// Transport flavors reserved by the wire contract.
    pub transport_modes: Vec<TransportKind>,
}

impl Default for DataFsV1Contract {
    fn default() -> Self {
        Self {
            userspace_service: true,
            single_volume: true,
            object_ids_are_64_bit: true,
            extent_layout: true,
            directory_index: true,
            logical_metadata_journal: true,
            journal_checksum: true,
            checkpoint: true,
            minimal_fsck: true,
            read_only_get_vmo: true,
            writable_mmap_v1: false,
            transport_modes: vec![TransportKind::ChannelRpc, TransportKind::SharedRing],
        }
    }
}

/// Kind of object tracked by the reference model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectKind {
    /// Indexed directory object.
    Directory,
    /// Extent-backed regular file.
    RegularFile,
}

/// Lifecycle state for one inode/object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectState {
    /// Reachable through at least one directory entry.
    Live,
    /// No directory entry points to this inode, but reclaim has not happened yet.
    OrphanPendingDelete,
    /// Inode has been reclaimed and must not remain referenced.
    Deleted,
}

/// One file extent in the logical data layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    /// Logical file offset in bytes.
    pub logical_offset: u64,
    /// Starting block identifier in the single modeled volume.
    pub block: u64,
    /// Extent length in bytes.
    pub len: u64,
}

/// One object/inode record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRecord {
    /// Stable object id.
    pub id: ObjectId,
    /// Object kind.
    pub kind: ObjectKind,
    /// Lifecycle state.
    pub state: ObjectState,
    /// Directory-entry reference count.
    pub link_count: u32,
    /// Logical size for file-like objects.
    pub size: u64,
    /// Extent map for regular files.
    pub extents: Vec<Extent>,
}

/// Persistent namespace state tracked by the reference model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelState {
    /// Objects keyed by object id.
    pub objects: BTreeMap<ObjectId, ObjectRecord>,
    /// Directory bindings: parent object id -> entry name -> child object id.
    pub directories: BTreeMap<ObjectId, BTreeMap<String, ObjectId>>,
    /// Most recent committed tx id.
    pub last_committed_tx: u64,
    /// Journal sequence number covered by the latest commit.
    pub last_committed_seq: u64,
    /// Last checkpointed tx id when present.
    pub last_checkpoint_tx: Option<u64>,
}

impl Default for ModelState {
    fn default() -> Self {
        let mut objects = BTreeMap::new();
        objects.insert(
            ROOT_ID,
            ObjectRecord {
                id: ROOT_ID,
                kind: ObjectKind::Directory,
                state: ObjectState::Live,
                link_count: 1,
                size: 0,
                extents: Vec::new(),
            },
        );
        let mut directories = BTreeMap::new();
        directories.insert(ROOT_ID, BTreeMap::new());
        Self {
            objects,
            directories,
            last_committed_tx: 0,
            last_committed_seq: 0,
            last_checkpoint_tx: None,
        }
    }
}

/// High-level metadata operation tracked by the model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    /// Create one directory beneath an existing parent.
    CreateDir {
        /// Absolute path for the new directory.
        path: String,
    },
    /// Create one regular file beneath an existing parent.
    CreateFile {
        /// Absolute path for the new file.
        path: String,
    },
    /// Replace the file extent map with one logical write.
    Write {
        /// Path to the file.
        path: String,
        /// Logical file offset.
        logical_offset: u64,
        /// Block id used by the new extent.
        block: u64,
        /// Length in bytes.
        len: u64,
    },
    /// Add one extra directory entry to an existing file.
    Link {
        /// Existing source path.
        src: String,
        /// New destination path.
        dst: String,
    },
    /// Move one existing directory entry.
    Rename {
        /// Existing source path.
        src: String,
        /// New destination path.
        dst: String,
    },
    /// Remove one existing directory entry.
    Unlink {
        /// Absolute path to remove.
        path: String,
    },
    /// Persist the journal/checkpoint boundary for the path.
    Fsync {
        /// Absolute path whose metadata durability boundary is being advanced.
        path: String,
    },
}

/// Built-in host scenarios used by the checker tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    /// Human-readable scenario name.
    pub name: String,
    /// Ordered operations executed by the model.
    pub operations: Vec<Operation>,
    /// Reserved recovery/session metadata for the scenario.
    pub recovery: RecoveryHandle,
}

/// One logical journal record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Stored checksum for the record payload.
    pub checksum: u64,
    /// Record payload.
    pub kind: JournalRecordKind,
}

impl JournalRecord {
    fn new(seq: u64, kind: JournalRecordKind) -> Self {
        let checksum = checksum_for(seq, &kind);
        Self {
            seq,
            checksum,
            kind,
        }
    }

    fn checksum_matches(&self) -> bool {
        self.checksum == checksum_for(self.seq, &self.kind)
    }
}

/// Record payload for the logical journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalRecordKind {
    /// Start one metadata transaction.
    BeginTx {
        /// Logical transaction identifier.
        tx_id: u64,
    },
    /// One logical metadata mutation inside a transaction.
    Mutation {
        /// Logical transaction identifier.
        tx_id: u64,
        /// High-level metadata mutation captured by the journal.
        op: Operation,
    },
    /// Commit one transaction.
    CommitTx {
        /// Logical transaction identifier.
        tx_id: u64,
    },
    /// Checkpoint covering the latest committed transaction.
    Checkpoint {
        /// Latest committed transaction included in the checkpoint.
        tx_id: u64,
    },
}

/// One reference-model instance with live state and journal history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReferenceModel {
    contract: DataFsV1Contract,
    next_object_id: ObjectId,
    next_tx_id: u64,
    next_seq: u64,
    state: ModelState,
    journal: Vec<JournalRecord>,
}

impl ReferenceModel {
    /// Build one fresh model with the frozen v1 contract.
    pub fn new(contract: DataFsV1Contract) -> Self {
        Self {
            contract,
            next_object_id: ROOT_ID + 1,
            next_tx_id: 1,
            next_seq: 1,
            state: ModelState::default(),
            journal: Vec::new(),
        }
    }

    /// Borrow the frozen v1 contract.
    pub fn contract(&self) -> &DataFsV1Contract {
        &self.contract
    }

    /// Borrow the current live state.
    pub fn state(&self) -> &ModelState {
        &self.state
    }

    /// Borrow the logical journal.
    pub fn journal(&self) -> &[JournalRecord] {
        &self.journal
    }

    /// Apply one high-level operation to the live state and append journal records.
    pub fn apply(&mut self, op: Operation) -> Result<(), ModelError> {
        match op {
            Operation::Fsync { path } => self.fsync(path.as_str()),
            op => {
                let tx_id = self.begin_tx();
                self.append(JournalRecordKind::Mutation {
                    tx_id,
                    op: op.clone(),
                });
                apply_mutation(&mut self.state, &mut self.next_object_id, op)?;
                self.append(JournalRecordKind::CommitTx { tx_id });
                self.state.last_committed_tx = tx_id;
                self.state.last_committed_seq = self.next_seq - 1;
                Ok(())
            }
        }
    }

    fn fsync(&mut self, path: &str) -> Result<(), ModelError> {
        let _ = self.state.lookup_path(path)?;
        let tx_id = self.begin_tx();
        self.append(JournalRecordKind::Mutation {
            tx_id,
            op: Operation::Fsync {
                path: path.to_string(),
            },
        });
        self.append(JournalRecordKind::CommitTx { tx_id });
        self.state.last_committed_tx = tx_id;
        self.state.last_committed_seq = self.next_seq - 1;
        self.append(JournalRecordKind::Checkpoint { tx_id });
        self.state.last_checkpoint_tx = Some(tx_id);
        self.collect_orphans();
        Ok(())
    }

    fn begin_tx(&mut self) -> u64 {
        let tx_id = self.next_tx_id;
        self.next_tx_id += 1;
        self.append(JournalRecordKind::BeginTx { tx_id });
        tx_id
    }

    fn append(&mut self, kind: JournalRecordKind) {
        let record = JournalRecord::new(self.next_seq, kind);
        self.next_seq += 1;
        self.journal.push(record);
    }

    fn collect_orphans(&mut self) {
        let orphan_ids = self
            .state
            .objects
            .iter()
            .filter_map(|(id, object)| {
                (object.state == ObjectState::OrphanPendingDelete).then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in orphan_ids {
            if let Some(object) = self.state.objects.get_mut(&id) {
                object.state = ObjectState::Deleted;
                object.extents.clear();
                object.size = 0;
            }
        }
    }
}

/// One injected fault used for crash/recovery exploration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultSpec {
    /// Truncate the journal after `seq`.
    DropAfterSeq(u64),
    /// Corrupt the checksum of one record at `seq`.
    CorruptSeq(u64),
    /// Remove every checkpoint record.
    DropAllCheckpoints,
}

/// One replay case emitted by the fault injector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCase {
    /// Scenario name.
    pub scenario: String,
    /// Injected fault.
    pub fault: FaultSpec,
    /// Frozen v1 contract.
    pub contract: DataFsV1Contract,
    /// Journal records before fault injection.
    pub journal: Vec<JournalRecord>,
    /// Reserved recovery/session metadata.
    pub recovery: RecoveryHandle,
}

/// One recovered replay result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayResult {
    /// Injected fault replayed by the harness.
    pub fault: FaultSpec,
    /// Recovered state.
    pub state: ModelState,
    /// Journal-level invariant violations.
    pub journal_violations: Vec<String>,
    /// State/fsck invariant violations.
    pub state_violations: Vec<String>,
    /// Sequence number where replay stopped when corruption was detected.
    pub stopped_at_seq: Option<u64>,
}

/// Summary returned by scenario exploration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorationReport {
    /// Scenario name.
    pub scenario: String,
    /// Number of replay cases exercised.
    pub cases_checked: usize,
    /// Number of clean replay cases with no violations.
    pub clean_cases: usize,
    /// Violations grouped by fault spec.
    pub failing_cases: Vec<ReplayResult>,
}

/// Error returned while mutating the reference model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelError {
    /// One path was malformed.
    InvalidPath(String),
    /// One requested path did not exist.
    NotFound(String),
    /// One requested path resolved to a directory when a file was required.
    NotFile(String),
    /// One requested path resolved to a file when a directory was required.
    NotDirectory(String),
    /// The destination path already existed.
    AlreadyExists(String),
    /// The operation would cross the single modeled volume boundary.
    CrossVolume(String, String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(f, "invalid path {path}"),
            Self::NotFound(path) => write!(f, "not found {path}"),
            Self::NotFile(path) => write!(f, "not a file {path}"),
            Self::NotDirectory(path) => write!(f, "not a directory {path}"),
            Self::AlreadyExists(path) => write!(f, "already exists {path}"),
            Self::CrossVolume(src, dst) => write!(f, "cross-volume operation {src} -> {dst}"),
        }
    }
}

impl std::error::Error for ModelError {}

/// Return the built-in scenarios used by the checker tool.
pub fn built_in_scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "rename-fsync".to_string(),
            operations: vec![
                Operation::CreateDir {
                    path: "/data".to_string(),
                },
                Operation::CreateFile {
                    path: "/data/a".to_string(),
                },
                Operation::Write {
                    path: "/data/a".to_string(),
                    logical_offset: 0,
                    block: 10,
                    len: 4096,
                },
                Operation::Rename {
                    src: "/data/a".to_string(),
                    dst: "/data/b".to_string(),
                },
                Operation::Fsync {
                    path: "/data/b".to_string(),
                },
            ],
            recovery: RecoveryHandle {
                session_id: 1,
                open_file_description_id: 7,
                reconnectable: true,
                transport: TransportKind::ChannelRpc,
            },
        },
        Scenario {
            name: "link-unlink".to_string(),
            operations: vec![
                Operation::CreateDir {
                    path: "/tmp".to_string(),
                },
                Operation::CreateFile {
                    path: "/tmp/original".to_string(),
                },
                Operation::Write {
                    path: "/tmp/original".to_string(),
                    logical_offset: 0,
                    block: 20,
                    len: 2048,
                },
                Operation::Link {
                    src: "/tmp/original".to_string(),
                    dst: "/tmp/linked".to_string(),
                },
                Operation::Unlink {
                    path: "/tmp/original".to_string(),
                },
                Operation::Fsync {
                    path: "/tmp/linked".to_string(),
                },
            ],
            recovery: RecoveryHandle {
                session_id: 2,
                open_file_description_id: 9,
                reconnectable: true,
                transport: TransportKind::ChannelRpc,
            },
        },
        Scenario {
            name: "extent-checkpoint".to_string(),
            operations: vec![
                Operation::CreateDir {
                    path: "/pkg".to_string(),
                },
                Operation::CreateFile {
                    path: "/pkg/resource".to_string(),
                },
                Operation::Write {
                    path: "/pkg/resource".to_string(),
                    logical_offset: 0,
                    block: 30,
                    len: 1024,
                },
                Operation::Write {
                    path: "/pkg/resource".to_string(),
                    logical_offset: 1024,
                    block: 31,
                    len: 1024,
                },
                Operation::Fsync {
                    path: "/pkg/resource".to_string(),
                },
            ],
            recovery: RecoveryHandle {
                session_id: 3,
                open_file_description_id: 11,
                reconnectable: true,
                transport: TransportKind::SharedRing,
            },
        },
    ]
}

/// Find one built-in scenario by name.
pub fn scenario_by_name(name: &str) -> Option<Scenario> {
    built_in_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == name)
}

/// Expand one scenario into concrete replay cases with injected faults.
pub fn inject_faults(scenario: &Scenario) -> Result<Vec<ReplayCase>, ModelError> {
    let mut model = ReferenceModel::new(DataFsV1Contract::default());
    for operation in &scenario.operations {
        model.apply(operation.clone())?;
    }

    let mut cases = Vec::new();
    let journal = model.journal().to_vec();
    cases.push(ReplayCase {
        scenario: scenario.name.clone(),
        fault: FaultSpec::DropAfterSeq(
            model.journal().last().map(|record| record.seq).unwrap_or(0),
        ),
        contract: model.contract().clone(),
        journal: journal.clone(),
        recovery: scenario.recovery,
    });
    for record in &journal {
        cases.push(ReplayCase {
            scenario: scenario.name.clone(),
            fault: FaultSpec::DropAfterSeq(record.seq.saturating_sub(1)),
            contract: model.contract().clone(),
            journal: journal.clone(),
            recovery: scenario.recovery,
        });
        cases.push(ReplayCase {
            scenario: scenario.name.clone(),
            fault: FaultSpec::CorruptSeq(record.seq),
            contract: model.contract().clone(),
            journal: journal.clone(),
            recovery: scenario.recovery,
        });
    }
    cases.push(ReplayCase {
        scenario: scenario.name.clone(),
        fault: FaultSpec::DropAllCheckpoints,
        contract: model.contract().clone(),
        journal,
        recovery: scenario.recovery,
    });
    Ok(cases)
}

/// Replay one injected crash case and run journal/state invariants.
pub fn replay_case(case: &ReplayCase) -> ReplayResult {
    let journal = apply_fault(&case.journal, &case.fault);
    let mut state = ModelState::default();
    let mut next_object_id = state
        .objects
        .keys()
        .next_back()
        .copied()
        .unwrap_or(ROOT_ID)
        .saturating_add(1);
    let mut open_txs = BTreeMap::<u64, Vec<Operation>>::new();
    let mut journal_violations = check_journal_invariants(&journal);
    let mut stopped_at_seq = None;
    let mut committed = BTreeSet::new();

    for record in &journal {
        if !record.checksum_matches() {
            stopped_at_seq = Some(record.seq);
            journal_violations.push(format!("checksum-mismatch:seq={}", record.seq));
            break;
        }
        match &record.kind {
            JournalRecordKind::BeginTx { tx_id } => {
                if open_txs.insert(*tx_id, Vec::new()).is_some() {
                    journal_violations.push(format!("duplicate-begin:tx={tx_id}"));
                    break;
                }
            }
            JournalRecordKind::Mutation { tx_id, op } => match open_txs.get_mut(tx_id) {
                Some(ops) => ops.push(op.clone()),
                None => {
                    journal_violations.push(format!("mutation-without-begin:tx={tx_id}"));
                    break;
                }
            },
            JournalRecordKind::CommitTx { tx_id } => {
                let Some(ops) = open_txs.remove(tx_id) else {
                    journal_violations.push(format!("commit-without-begin:tx={tx_id}"));
                    break;
                };
                if committed.contains(tx_id) {
                    journal_violations.push(format!("duplicate-commit:tx={tx_id}"));
                    break;
                }
                let mut replay_failed = false;
                for op in ops {
                    if matches!(op, Operation::Fsync { .. }) {
                        continue;
                    }
                    if let Err(error) = apply_mutation(&mut state, &mut next_object_id, op) {
                        journal_violations.push(format!("replay-apply-error:{error:?}"));
                        replay_failed = true;
                        break;
                    }
                }
                if replay_failed {
                    break;
                }
                committed.insert(*tx_id);
                state.last_committed_tx = *tx_id;
                state.last_committed_seq = record.seq;
            }
            JournalRecordKind::Checkpoint { tx_id } => {
                if !committed.contains(tx_id) {
                    journal_violations.push(format!("checkpoint-before-commit:tx={tx_id}"));
                    break;
                }
                state.last_checkpoint_tx = Some(*tx_id);
                collect_orphans_in_state(&mut state);
            }
        }
    }

    let state_violations = check_state_invariants(&state);
    ReplayResult {
        fault: case.fault.clone(),
        state,
        journal_violations,
        state_violations,
        stopped_at_seq,
    }
}

/// Explore one built-in scenario by enumerating its crash/fault cases.
pub fn explore_scenario(scenario: &Scenario) -> Result<ExplorationReport, ModelError> {
    let cases = inject_faults(scenario)?;
    let mut clean_cases = 0usize;
    let mut failing_cases = Vec::new();

    for case in cases {
        let result = replay_case(&case);
        if result.journal_violations.is_empty() && result.state_violations.is_empty() {
            clean_cases += 1;
        } else {
            failing_cases.push(result);
        }
    }

    Ok(ExplorationReport {
        scenario: scenario.name.clone(),
        cases_checked: clean_cases + failing_cases.len(),
        clean_cases,
        failing_cases,
    })
}

/// Run one minimal fsck-style invariant pass over a recovered state.
pub fn check_state_invariants(state: &ModelState) -> Vec<String> {
    let mut violations = Vec::new();

    let Some(root) = state.objects.get(&ROOT_ID) else {
        violations.push("missing-root".to_string());
        return violations;
    };
    if root.kind != ObjectKind::Directory {
        violations.push("root-not-directory".to_string());
    }
    if root.state != ObjectState::Live {
        violations.push("root-not-live".to_string());
    }

    let mut inbound = BTreeMap::<ObjectId, u32>::new();
    inbound.insert(ROOT_ID, 1);
    for (directory_id, entries) in &state.directories {
        if !state.objects.contains_key(directory_id) {
            violations.push(format!("dangling-directory-table:{directory_id}"));
            continue;
        }
        for (name, target) in entries {
            if name.is_empty() || name.contains('/') {
                violations.push(format!("invalid-entry-name:{directory_id}:{name}"));
            }
            if !state.objects.contains_key(target) {
                violations.push(format!("dangling-entry:{directory_id}:{name}->{target}"));
            } else {
                *inbound.entry(*target).or_insert(0) += 1;
            }
        }
    }

    for (id, object) in &state.objects {
        let expected_links = *inbound.get(id).unwrap_or(&0);
        if object.kind == ObjectKind::Directory && !state.directories.contains_key(id) {
            violations.push(format!("directory-missing-index:{id}"));
        }
        if object.link_count != expected_links {
            violations.push(format!(
                "link-count-mismatch:{id}:expected={expected_links}:actual={}",
                object.link_count
            ));
        }
        match object.state {
            ObjectState::Live if object.link_count == 0 => {
                violations.push(format!("live-object-without-links:{id}"));
            }
            ObjectState::OrphanPendingDelete if object.link_count != 0 => {
                violations.push(format!("orphan-still-linked:{id}"));
            }
            ObjectState::Deleted if object.link_count != 0 => {
                violations.push(format!("deleted-object-still-linked:{id}"));
            }
            _ => {}
        }
        if object.kind == ObjectKind::RegularFile {
            for pair in object.extents.windows(2) {
                if let [left, right] = pair
                    && left.logical_offset + left.len > right.logical_offset
                {
                    violations.push(format!("overlapping-extents:{id}"));
                }
            }
        }
    }

    violations
}

/// Run invariant checks over one journal stream before replay.
pub fn check_journal_invariants(journal: &[JournalRecord]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut last_seq = 0u64;
    let mut open_txs = BTreeSet::new();
    let mut committed = BTreeSet::new();
    for record in journal {
        if record.seq <= last_seq {
            violations.push(format!("non-monotonic-seq:{}", record.seq));
        }
        last_seq = record.seq;
        match &record.kind {
            JournalRecordKind::BeginTx { tx_id } => {
                if !open_txs.insert(*tx_id) {
                    violations.push(format!("duplicate-begin:tx={tx_id}"));
                }
            }
            JournalRecordKind::Mutation { tx_id, .. } => {
                if !open_txs.contains(tx_id) {
                    violations.push(format!("mutation-without-open-tx:tx={tx_id}"));
                }
            }
            JournalRecordKind::CommitTx { tx_id } => {
                if !open_txs.remove(tx_id) {
                    violations.push(format!("commit-without-open-tx:tx={tx_id}"));
                }
                if !committed.insert(*tx_id) {
                    violations.push(format!("duplicate-commit:tx={tx_id}"));
                }
            }
            JournalRecordKind::Checkpoint { tx_id } => {
                if !committed.contains(tx_id) {
                    violations.push(format!("checkpoint-without-commit:tx={tx_id}"));
                }
            }
        }
        if !record.checksum_matches() {
            violations.push(format!("checksum-mismatch:seq={}", record.seq));
        }
    }
    violations
}

fn apply_fault(journal: &[JournalRecord], fault: &FaultSpec) -> Vec<JournalRecord> {
    match fault {
        FaultSpec::DropAfterSeq(seq) => journal
            .iter()
            .filter(|record| record.seq <= *seq)
            .cloned()
            .collect(),
        FaultSpec::CorruptSeq(seq) => journal
            .iter()
            .cloned()
            .map(|mut record| {
                if record.seq == *seq {
                    record.checksum ^= 0x55aa_55aa_55aa_55aa;
                }
                record
            })
            .collect(),
        FaultSpec::DropAllCheckpoints => journal
            .iter()
            .filter(|record| !matches!(record.kind, JournalRecordKind::Checkpoint { .. }))
            .cloned()
            .collect(),
    }
}

fn checksum_for(seq: u64, kind: &JournalRecordKind) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seq.hash(&mut hasher);
    kind.hash(&mut hasher);
    hasher.finish()
}

impl Hash for JournalRecordKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::BeginTx { tx_id } => {
                1u8.hash(state);
                tx_id.hash(state);
            }
            Self::Mutation { tx_id, op } => {
                2u8.hash(state);
                tx_id.hash(state);
                format!("{op:?}").hash(state);
            }
            Self::CommitTx { tx_id } => {
                3u8.hash(state);
                tx_id.hash(state);
            }
            Self::Checkpoint { tx_id } => {
                4u8.hash(state);
                tx_id.hash(state);
            }
        }
    }
}

fn apply_mutation(
    state: &mut ModelState,
    next_object_id: &mut ObjectId,
    op: Operation,
) -> Result<(), ModelError> {
    match op {
        Operation::CreateDir { path } => {
            let (parent, leaf) = split_parent_and_leaf(path.as_str())?;
            let parent_id = state.lookup_path(parent.as_str())?;
            ensure_directory(state, parent_id, parent.as_str())?;
            ensure_missing(state, parent_id, leaf.as_str(), path.as_str())?;
            let id = *next_object_id;
            *next_object_id += 1;
            state.objects.insert(
                id,
                ObjectRecord {
                    id,
                    kind: ObjectKind::Directory,
                    state: ObjectState::Live,
                    link_count: 1,
                    size: 0,
                    extents: Vec::new(),
                },
            );
            state.directories.insert(id, BTreeMap::new());
            state
                .directories
                .get_mut(&parent_id)
                .expect("directory exists")
                .insert(leaf, id);
            Ok(())
        }
        Operation::CreateFile { path } => {
            let (parent, leaf) = split_parent_and_leaf(path.as_str())?;
            let parent_id = state.lookup_path(parent.as_str())?;
            ensure_directory(state, parent_id, parent.as_str())?;
            ensure_missing(state, parent_id, leaf.as_str(), path.as_str())?;
            let id = *next_object_id;
            *next_object_id += 1;
            state.objects.insert(
                id,
                ObjectRecord {
                    id,
                    kind: ObjectKind::RegularFile,
                    state: ObjectState::Live,
                    link_count: 1,
                    size: 0,
                    extents: Vec::new(),
                },
            );
            state
                .directories
                .get_mut(&parent_id)
                .expect("directory exists")
                .insert(leaf, id);
            Ok(())
        }
        Operation::Write {
            path,
            logical_offset,
            block,
            len,
        } => {
            let id = state.lookup_path(path.as_str())?;
            let object = state.object_mut(id)?;
            if object.kind != ObjectKind::RegularFile {
                return Err(ModelError::NotFile(path));
            }
            object.extents.push(Extent {
                logical_offset,
                block,
                len,
            });
            object.extents.sort_by_key(|extent| extent.logical_offset);
            object.size = object.size.max(logical_offset.saturating_add(len));
            Ok(())
        }
        Operation::Link { src, dst } => {
            let src_id = state.lookup_path(src.as_str())?;
            if state.object(src_id)?.kind != ObjectKind::RegularFile {
                return Err(ModelError::NotFile(src));
            }
            let (dst_parent, dst_leaf) = split_parent_and_leaf(dst.as_str())?;
            let dst_parent_id = state.lookup_path(dst_parent.as_str())?;
            ensure_directory(state, dst_parent_id, dst_parent.as_str())?;
            ensure_missing(state, dst_parent_id, dst_leaf.as_str(), dst.as_str())?;
            state
                .directories
                .get_mut(&dst_parent_id)
                .expect("directory exists")
                .insert(dst_leaf, src_id);
            state.object_mut(src_id)?.link_count += 1;
            Ok(())
        }
        Operation::Rename { src, dst } => {
            let (src_parent, src_leaf) = split_parent_and_leaf(src.as_str())?;
            let (dst_parent, dst_leaf) = split_parent_and_leaf(dst.as_str())?;
            let src_parent_id = state.lookup_path(src_parent.as_str())?;
            let dst_parent_id = state.lookup_path(dst_parent.as_str())?;
            ensure_directory(state, src_parent_id, src_parent.as_str())?;
            ensure_directory(state, dst_parent_id, dst_parent.as_str())?;
            ensure_missing(state, dst_parent_id, dst_leaf.as_str(), dst.as_str())?;
            let object = state
                .directories
                .get_mut(&src_parent_id)
                .expect("directory exists")
                .remove(src_leaf.as_str())
                .ok_or_else(|| ModelError::NotFound(src.clone()))?;
            state
                .directories
                .get_mut(&dst_parent_id)
                .expect("directory exists")
                .insert(dst_leaf, object);
            Ok(())
        }
        Operation::Unlink { path } => {
            let (parent, leaf) = split_parent_and_leaf(path.as_str())?;
            let parent_id = state.lookup_path(parent.as_str())?;
            ensure_directory(state, parent_id, parent.as_str())?;
            let object_id = state
                .directories
                .get_mut(&parent_id)
                .expect("directory exists")
                .remove(leaf.as_str())
                .ok_or_else(|| ModelError::NotFound(path.clone()))?;
            let object = state.object_mut(object_id)?;
            if object.kind == ObjectKind::Directory {
                return Err(ModelError::NotDirectory(path));
            }
            object.link_count = object.link_count.saturating_sub(1);
            if object.link_count == 0 {
                object.state = ObjectState::OrphanPendingDelete;
            }
            Ok(())
        }
        Operation::Fsync { .. } => unreachable!("fsync handled separately"),
    }
}

fn ensure_directory(state: &ModelState, id: ObjectId, path: &str) -> Result<(), ModelError> {
    if state.object(id)?.kind == ObjectKind::Directory {
        Ok(())
    } else {
        Err(ModelError::NotDirectory(path.to_string()))
    }
}

fn ensure_missing(
    state: &ModelState,
    parent_id: ObjectId,
    leaf: &str,
    path: &str,
) -> Result<(), ModelError> {
    if state
        .directories
        .get(&parent_id)
        .is_some_and(|entries| entries.contains_key(leaf))
    {
        Err(ModelError::AlreadyExists(path.to_string()))
    } else {
        Ok(())
    }
}

fn collect_orphans_in_state(state: &mut ModelState) {
    for object in state.objects.values_mut() {
        if object.state == ObjectState::OrphanPendingDelete {
            object.state = ObjectState::Deleted;
            object.extents.clear();
            object.size = 0;
        }
    }
}

fn split_parent_and_leaf(path: &str) -> Result<(String, String), ModelError> {
    if !path.starts_with('/') || path == "/" {
        return Err(ModelError::InvalidPath(path.to_string()));
    }
    let normalized = normalize_path(path)?;
    let (parent, leaf) = normalized
        .rsplit_once('/')
        .ok_or_else(|| ModelError::InvalidPath(path.to_string()))?;
    if leaf.is_empty() {
        return Err(ModelError::InvalidPath(path.to_string()));
    }
    Ok((
        if parent.is_empty() {
            "/".to_string()
        } else {
            parent.to_string()
        },
        leaf.to_string(),
    ))
}

fn normalize_path(path: &str) -> Result<String, ModelError> {
    if !path.starts_with('/') {
        return Err(ModelError::InvalidPath(path.to_string()));
    }
    let mut components = Vec::<String>::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        match component {
            "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component.to_string()),
        }
    }
    if components.is_empty() {
        return Ok("/".to_string());
    }
    let mut normalized = String::new();
    for component in components {
        normalized.push('/');
        normalized.push_str(component.as_str());
    }
    Ok(normalized)
}

impl ModelState {
    fn lookup_path(&self, path: &str) -> Result<ObjectId, ModelError> {
        let normalized = normalize_path(path)?;
        if normalized == "/" {
            return Ok(ROOT_ID);
        }
        let mut current = ROOT_ID;
        for component in normalized
            .split('/')
            .filter(|component| !component.is_empty())
        {
            let entries = self
                .directories
                .get(&current)
                .ok_or_else(|| ModelError::NotDirectory(path.to_string()))?;
            current = *entries
                .get(component)
                .ok_or_else(|| ModelError::NotFound(path.to_string()))?;
        }
        Ok(current)
    }

    fn object(&self, id: ObjectId) -> Result<&ObjectRecord, ModelError> {
        self.objects
            .get(&id)
            .ok_or_else(|| ModelError::NotFound(format!("object:{id}")))
    }

    fn object_mut(&mut self, id: ObjectId) -> Result<&mut ObjectRecord, ModelError> {
        self.objects
            .get_mut(&id)
            .ok_or_else(|| ModelError::NotFound(format!("object:{id}")))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DataFsV1Contract, FaultSpec, JournalRecord, JournalRecordKind, ObjectState, Operation,
        ReferenceModel, built_in_scenarios, check_journal_invariants, check_state_invariants,
        inject_faults, replay_case,
    };

    #[test]
    fn contract_freezes_v1_without_writable_mmap() {
        let contract = DataFsV1Contract::default();
        assert!(contract.userspace_service);
        assert!(contract.read_only_get_vmo);
        assert!(!contract.writable_mmap_v1);
    }

    #[test]
    fn rename_and_fsync_scenario_replays_without_state_invariant_failures() {
        let scenario = built_in_scenarios()
            .into_iter()
            .find(|scenario| scenario.name == "rename-fsync")
            .expect("scenario");
        let cases = inject_faults(&scenario).expect("inject");
        for case in &cases {
            let result = replay_case(case);
            assert!(
                result.state_violations.is_empty(),
                "fault {:?} produced state violations {:?}",
                result.fault,
                result.state_violations
            );
        }
    }

    #[test]
    fn orphan_is_collected_after_fsync_checkpoint() {
        let mut model = ReferenceModel::new(DataFsV1Contract::default());
        model
            .apply(Operation::CreateDir {
                path: "/tmp".to_string(),
            })
            .expect("mkdir");
        model
            .apply(Operation::CreateFile {
                path: "/tmp/file".to_string(),
            })
            .expect("create");
        model
            .apply(Operation::Unlink {
                path: "/tmp/file".to_string(),
            })
            .expect("unlink");
        let object_id = model.state().lookup_path("/tmp").expect("tmp dir");
        assert_eq!(model.state().directories[&object_id].len(), 0);
        model
            .apply(Operation::Fsync {
                path: "/tmp".to_string(),
            })
            .expect("fsync tmp");
        let orphan = model
            .state()
            .objects
            .values()
            .find(|object| object.state == ObjectState::Deleted)
            .expect("deleted inode after checkpoint");
        assert_eq!(orphan.link_count, 0);
    }

    #[test]
    fn journal_checker_detects_checksum_corruption() {
        let record = JournalRecord {
            seq: 1,
            checksum: 0,
            kind: JournalRecordKind::BeginTx { tx_id: 7 },
        };
        let violations = check_journal_invariants(&[record]);
        assert!(
            violations
                .iter()
                .any(|entry| entry.contains("checksum-mismatch"))
        );
    }

    #[test]
    fn replay_reports_corruption_stop_point() {
        let scenario = built_in_scenarios().remove(0);
        let case = inject_faults(&scenario)
            .expect("inject")
            .into_iter()
            .find(|case| matches!(case.fault, FaultSpec::CorruptSeq(_)))
            .expect("corrupt case");
        let result = replay_case(&case);
        assert!(result.stopped_at_seq.is_some());
    }

    #[test]
    fn fsck_invariants_accept_clean_default_state() {
        let model = ReferenceModel::new(DataFsV1Contract::default());
        assert!(check_state_invariants(model.state()).is_empty());
    }
}
