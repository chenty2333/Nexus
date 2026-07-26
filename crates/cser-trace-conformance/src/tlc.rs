//! Deterministic TLC invocation that produces replayable counterexamples.
//!
//! The lane reuses the repository's `expect_reachable` pattern from
//! `specs/cser/check.sh`: a witness invariant asserts that an interesting
//! state is unreachable, and TLC is required to refute it. The refutation is
//! the behavior this crate replays, so a witness that stops failing is a
//! coverage regression, not a success.
//!
//! Runs are hermetic. Each witness gets a fresh temporary directory holding a
//! copy of `Cser.tla`, a generated module that extends it with the witness
//! definitions, and a copy of `CserMC.cfg` with `INVARIANT <witness>`
//! appended. TLC runs with a single worker so the shortest counterexample it
//! reports does not depend on scheduling.

use core::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::sha256;

/// Directory holding the repository's pinned TLA+ tools snapshot.
pub const PINNED_TOOLS_DIR: &str = "third_party/tlaplus/1.8.0-227f61b";
/// File name of the pinned model checker.
pub const PINNED_JAR_NAME: &str = "tla2tools-227f61b.jar";
/// Environment variable that may point at an equally pinned JAR copy.
pub const JAR_ENV: &str = "TLA2TOOLS_JAR";

const RUN_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A reachability witness: an invariant TLC must refute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Witness {
    /// Invariant name.
    pub invariant: &'static str,
    /// TLA+ text defining the invariant, and any state constraint, in a
    /// generated module extending the family's specification.
    ///
    /// `None` means the specification already releases this invariant, in
    /// which case the run is exactly `check.sh`'s `expect_reachable`: the
    /// released module and config, plus `INVARIANT` and `CONSTRAINT` lines.
    /// Preferring `None` keeps the replayed behaviors tied to witnesses the
    /// repository already publishes rather than to ones this lane invented.
    pub definition: Option<&'static str>,
    /// Optional state-constraint operator that shapes the search so the
    /// shortest counterexample exercises the intended operation.
    pub constraint: Option<&'static str>,
    /// Human-readable statement of the state the witness reaches.
    pub description: &'static str,
}

/// A specification family: one TLA+ module, one released base configuration,
/// and the witnesses whose refutations this lane replays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FamilySpec {
    /// Module name without the `.tla` suffix.
    pub module: &'static str,
    /// Base configuration file name within `specs/cser/`.
    pub base_config: &'static str,
    /// Witnesses replayed for this family.
    pub witnesses: &'static [Witness],
}

impl FamilySpec {
    /// Returns the module TLC is pointed at for `witness`.
    #[must_use]
    pub fn entry_module(&self, witness: &Witness) -> String {
        if witness.definition.is_some() {
            format!("{}Witness", self.module)
        } else {
            String::from(self.module)
        }
    }
}

/// Failure while producing a counterexample.
#[derive(Debug)]
pub enum TlcError {
    /// A filesystem operation failed.
    Io {
        /// What the lane was doing.
        context: &'static str,
        /// Underlying failure.
        source: io::Error,
    },
    /// The pinned JAR is absent.
    JarMissing {
        /// Path that was searched.
        path: PathBuf,
    },
    /// The JAR bytes do not match the repository's pinned digest.
    JarDigestMismatch {
        /// Digest recorded in `SHA256SUMS`.
        expected: String,
        /// Digest of the JAR that would have been used.
        actual: String,
    },
    /// The pinned checksum file is not a single-entry `sha256sum` listing.
    ChecksumsMalformed {
        /// Path of the checksum file.
        path: PathBuf,
    },
    /// `java` could not be started.
    JavaUnavailable {
        /// Underlying failure.
        source: io::Error,
    },
    /// TLC did not finish within the lane's time bound.
    Timeout {
        /// Witness that was being produced.
        invariant: &'static str,
    },
    /// TLC completed without refuting the witness invariant.
    WitnessNotFound {
        /// Witness that was expected to fail.
        invariant: &'static str,
        /// Tail of the run log.
        log_tail: String,
    },
}

impl fmt::Display for TlcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::JarMissing { path } => {
                write!(
                    formatter,
                    "pinned TLA+ tools JAR is missing: {}",
                    path.display()
                )
            }
            Self::JarDigestMismatch { expected, actual } => write!(
                formatter,
                "TLA+ tools JAR digest {actual} does not match the pinned {expected}"
            ),
            Self::ChecksumsMalformed { path } => {
                write!(formatter, "malformed checksum file: {}", path.display())
            }
            Self::JavaUnavailable { source } => {
                write!(formatter, "could not start java: {source}")
            }
            Self::Timeout { invariant } => {
                write!(formatter, "TLC exceeded the time bound for {invariant}")
            }
            Self::WitnessNotFound {
                invariant,
                log_tail,
            } => write!(
                formatter,
                "TLC did not refute {invariant}; the witness state is unreachable\n{log_tail}"
            ),
        }
    }
}

impl std::error::Error for TlcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::JavaUnavailable { source } => Some(source),
            _ => None,
        }
    }
}

/// Runs witnesses against any specification family in `specs/cser/`.
#[derive(Clone, Debug)]
pub struct WitnessRunner {
    jar: PathBuf,
    specs: PathBuf,
}

impl WitnessRunner {
    /// Resolves the pinned model checker and baseline specification.
    ///
    /// # Errors
    ///
    /// Returns [`TlcError`] when the JAR is absent or its bytes differ from
    /// the digest recorded in the vendored `SHA256SUMS`.
    pub fn new(repo_root: &Path) -> Result<Self, TlcError> {
        let tools = repo_root.join(PINNED_TOOLS_DIR);
        let jar = match std::env::var_os(JAR_ENV) {
            Some(value) => PathBuf::from(value),
            None => tools.join(PINNED_JAR_NAME),
        };
        if !jar.is_file() {
            return Err(TlcError::JarMissing { path: jar });
        }
        verify_digest(&jar, &tools.join("SHA256SUMS"))?;
        Ok(Self {
            jar,
            specs: repo_root.join("specs/cser"),
        })
    }

    /// Produces the counterexample log for one witness.
    ///
    /// # Errors
    ///
    /// Returns [`TlcError`] when the run cannot be started, exceeds the time
    /// bound, or completes without refuting the witness invariant.
    pub fn run(&self, family: &FamilySpec, witness: &Witness) -> Result<String, TlcError> {
        let workspace = Workspace::create()?;
        let directory = workspace.path();
        let entry = family.entry_module(witness);

        copy(
            &self.specs.join(format!("{}.tla", family.module)),
            &directory.join(format!("{}.tla", family.module)),
        )?;
        let base_config = read(&self.specs.join(family.base_config))?;
        let mut config = format!("{base_config}\nINVARIANT {}\n", witness.invariant);
        if let Some(constraint) = witness.constraint {
            config.push_str(&format!("CONSTRAINT {constraint}\n"));
        }
        write(&directory.join(format!("{entry}.cfg")), &config)?;
        if let Some(definition) = witness.definition {
            write(
                &directory.join(format!("{entry}.tla")),
                &witness_module(&entry, family.module, definition),
            )?;
        }

        let log_path = directory.join("tlc.log");
        let log_file = fs::File::create(&log_path).map_err(|source| TlcError::Io {
            context: "creating the TLC log",
            source,
        })?;
        let errors = log_file.try_clone().map_err(|source| TlcError::Io {
            context: "duplicating the TLC log handle",
            source,
        })?;
        let child = Command::new("java")
            .current_dir(directory)
            .arg("-XX:+UseParallelGC")
            .arg("-cp")
            .arg(&self.jar)
            .args(["tlc2.TLC", "-cleanup", "-workers", "1", "-config"])
            .arg(format!("{entry}.cfg"))
            .arg(format!("{entry}.tla"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(errors))
            .spawn()
            .map_err(|source| TlcError::JavaUnavailable { source })?;

        let refuted = wait_bounded(child, witness.invariant)?;
        let log = read(&log_path)?;
        if refuted {
            return Err(TlcError::WitnessNotFound {
                invariant: witness.invariant,
                log_tail: tail(&log),
            });
        }
        Ok(log)
    }
}

fn witness_module(entry: &str, extends: &str, definition: &str) -> String {
    format!(
        "---------------------------- MODULE {entry} ----------------------------\n\
         EXTENDS {extends}\n\
         \n\
         {definition}\n\
         \n\
         =============================================================================\n"
    )
}

/// Waits for TLC and reports whether it exited successfully, meaning the
/// witness invariant held everywhere and no counterexample exists.
fn wait_bounded(mut child: Child, invariant: &'static str) -> Result<bool, TlcError> {
    let deadline = Instant::now() + RUN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) => {}
            Err(source) => {
                return Err(TlcError::Io {
                    context: "waiting for TLC",
                    source,
                });
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TlcError::Timeout { invariant });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn verify_digest(jar: &Path, checksums: &Path) -> Result<(), TlcError> {
    let listing = read(checksums)?;
    let mut entries = listing.lines().filter(|line| !line.trim().is_empty());
    let entry = entries
        .next()
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| TlcError::ChecksumsMalformed {
            path: checksums.to_path_buf(),
        })?;
    if entries.next().is_some() || entry.len() != 64 {
        return Err(TlcError::ChecksumsMalformed {
            path: checksums.to_path_buf(),
        });
    }
    let bytes = fs::read(jar).map_err(|source| TlcError::Io {
        context: "reading the TLA+ tools JAR",
        source,
    })?;
    let actual = sha256::hex_digest(&bytes);
    if actual != entry {
        return Err(TlcError::JarDigestMismatch {
            expected: entry.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn tail(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    let start = lines.len().saturating_sub(20);
    lines[start..].join("\n")
}

fn copy(from: &Path, to: &Path) -> Result<(), TlcError> {
    fs::copy(from, to)
        .map(|_| ())
        .map_err(|source| TlcError::Io {
            context: "copying a specification file",
            source,
        })
}

fn read(path: &Path) -> Result<String, TlcError> {
    fs::read_to_string(path).map_err(|source| TlcError::Io {
        context: "reading a specification file",
        source,
    })
}

fn write(path: &Path, contents: &str) -> Result<(), TlcError> {
    fs::write(path, contents).map_err(|source| TlcError::Io {
        context: "writing a generated specification file",
        source,
    })
}

/// A temporary directory removed when the run finishes.
#[derive(Debug)]
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn create() -> Result<Self, TlcError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cser-trace-conformance-{}-{nanos}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).map_err(|source| TlcError::Io {
            context: "creating the TLC workspace",
            source,
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
