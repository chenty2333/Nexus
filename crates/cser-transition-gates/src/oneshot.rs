// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_GATE_NONCE: AtomicU64 = AtomicU64::new(1);

/// Caller-namespaced opaque identity for one bounded continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneShotToken {
    gate_nonce: u64,
    instance_id: u64,
    id: u64,
    generation: u64,
}

impl OneShotToken {
    pub const fn instance_id(self) -> u64 {
        self.instance_id
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneShotError {
    InvalidIdentity,
    InstanceNamespaceExhausted,
    ForeignInstance,
    StaleToken,
    InvalidReceipt,
    AlreadyTerminal,
    ReceiptAlreadyConsumed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TerminalReceipt<T: Copy + Eq> {
    token: OneShotToken,
    outcome: T,
}

impl<T: Copy + Eq> TerminalReceipt<T> {
    pub const fn token(&self) -> OneShotToken {
        self.token
    }

    pub const fn outcome(&self) -> T {
        self.outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneShotProjection<T: Copy + Eq> {
    token: OneShotToken,
    terminal: Option<T>,
    receipt_consumed: bool,
}

impl<T: Copy + Eq> OneShotProjection<T> {
    pub const fn token(self) -> OneShotToken {
        self.token
    }

    pub const fn terminal(self) -> Option<T> {
        self.terminal
    }

    pub const fn receipt_consumed(self) -> bool {
        self.receipt_consumed
    }
}

/// Single-winner terminal gate used by continuations and retained effects.
///
/// `instance_id` is a caller-owned semantic namespace. Each construction also
/// receives an internal process-unique nonce, so reconstructing the same public
/// triple cannot mint a receipt accepted by the original gate.
#[derive(Debug, Eq, PartialEq)]
pub struct OneShotGate<T: Copy + Eq> {
    token: OneShotToken,
    terminal: Option<T>,
    receipt_consumed: bool,
}

impl<T: Copy + Eq> OneShotGate<T> {
    pub fn new(instance_id: u64, id: u64, generation: u64) -> Result<Self, OneShotError> {
        if instance_id == 0 || id == 0 || generation == 0 {
            return Err(OneShotError::InvalidIdentity);
        }
        let gate_nonce = next_gate_nonce()?;
        Ok(Self {
            token: OneShotToken {
                gate_nonce,
                instance_id,
                id,
                generation,
            },
            terminal: None,
            receipt_consumed: false,
        })
    }

    pub const fn token(&self) -> OneShotToken {
        self.token
    }

    pub const fn terminal(&self) -> Option<T> {
        self.terminal
    }

    pub const fn projection(&self) -> OneShotProjection<T> {
        OneShotProjection {
            token: self.token,
            terminal: self.terminal,
            receipt_consumed: self.receipt_consumed,
        }
    }

    pub fn try_terminalize(
        &mut self,
        token: OneShotToken,
        outcome: T,
    ) -> Result<TerminalReceipt<T>, OneShotError> {
        self.validate_token(token)?;
        if self.terminal.is_some() {
            return Err(OneShotError::AlreadyTerminal);
        }
        self.terminal = Some(outcome);
        Ok(TerminalReceipt { token, outcome })
    }

    pub fn consume_terminal(&mut self, receipt: &TerminalReceipt<T>) -> Result<(), OneShotError> {
        self.validate_token(receipt.token)?;
        if self.terminal != Some(receipt.outcome) {
            return Err(OneShotError::InvalidReceipt);
        }
        if self.receipt_consumed {
            return Err(OneShotError::ReceiptAlreadyConsumed);
        }
        self.receipt_consumed = true;
        Ok(())
    }

    fn validate_token(&self, token: OneShotToken) -> Result<(), OneShotError> {
        if token.gate_nonce != self.token.gate_nonce || token.instance_id != self.token.instance_id
        {
            return Err(OneShotError::ForeignInstance);
        }
        if token.id != self.token.id || token.generation != self.token.generation {
            return Err(OneShotError::StaleToken);
        }
        Ok(())
    }
}

fn next_gate_nonce() -> Result<u64, OneShotError> {
    NEXT_GATE_NONCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| OneShotError::InstanceNamespaceExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminalization_is_single_winner_and_failures_do_not_mutate() {
        let mut gate = OneShotGate::new(0x7001, 7, 3).unwrap();
        let mut foreign = OneShotGate::new(0x7002, 7, 3).unwrap();
        let token = gate.token();
        let foreign_token = foreign.token();

        let before_gate = gate.projection();
        let before_foreign = foreign.projection();
        assert_eq!(
            gate.try_terminalize(foreign_token, 11_u8),
            Err(OneShotError::ForeignInstance)
        );
        assert_eq!(gate.projection(), before_gate);
        assert_eq!(
            foreign.try_terminalize(token, 12_u8),
            Err(OneShotError::ForeignInstance)
        );
        assert_eq!(foreign.projection(), before_foreign);

        let receipt = gate.try_terminalize(token, 11_u8).unwrap();
        assert_eq!(receipt.outcome(), 11);
        let foreign_receipt = foreign.try_terminalize(foreign_token, 12_u8).unwrap();
        let before_gate = gate.projection();
        let before_foreign = foreign.projection();
        assert_eq!(
            gate.consume_terminal(&foreign_receipt),
            Err(OneShotError::ForeignInstance)
        );
        assert_eq!(gate.projection(), before_gate);
        assert_eq!(
            foreign.consume_terminal(&receipt),
            Err(OneShotError::ForeignInstance)
        );
        assert_eq!(foreign.projection(), before_foreign);

        gate.consume_terminal(&receipt).unwrap();
        foreign.consume_terminal(&foreign_receipt).unwrap();
        assert!(gate.projection().receipt_consumed());
        assert!(foreign.projection().receipt_consumed());

        let before = gate.projection();
        assert_eq!(
            gate.try_terminalize(token, 12),
            Err(OneShotError::AlreadyTerminal)
        );
        assert_eq!(gate.projection(), before);
        assert_eq!(
            gate.consume_terminal(&receipt),
            Err(OneShotError::ReceiptAlreadyConsumed)
        );
        assert_eq!(gate.projection(), before);

        let mut detached = OneShotGate::new(0x7001, 7, 3).unwrap();
        let detached_receipt = detached.try_terminalize(detached.token(), 11_u8).unwrap();
        let before = gate.projection();
        assert_eq!(
            gate.consume_terminal(&detached_receipt),
            Err(OneShotError::ForeignInstance)
        );
        assert_eq!(gate.projection(), before);
    }
}
