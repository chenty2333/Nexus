// SPDX-License-Identifier: MPL-2.0

/// Unforgeable identity for one bounded continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneShotToken {
    id: u64,
    generation: u64,
}

impl OneShotToken {
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
    StaleToken,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalReceipt<T: Copy + Eq> {
    token: OneShotToken,
    outcome: T,
}

impl<T: Copy + Eq> TerminalReceipt<T> {
    pub const fn token(self) -> OneShotToken {
        self.token
    }

    pub const fn outcome(self) -> T {
        self.outcome
    }
}

/// Single-winner terminal gate used by continuations and retained effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneShotGate<T: Copy + Eq> {
    token: OneShotToken,
    terminal: Option<T>,
}

impl<T: Copy + Eq> OneShotGate<T> {
    pub fn new(id: u64, generation: u64) -> Result<Self, OneShotError> {
        if id == 0 || generation == 0 {
            return Err(OneShotError::InvalidIdentity);
        }
        Ok(Self {
            token: OneShotToken { id, generation },
            terminal: None,
        })
    }

    pub const fn token(&self) -> OneShotToken {
        self.token
    }

    pub const fn terminal(&self) -> Option<T> {
        self.terminal
    }

    pub fn try_terminalize(
        &mut self,
        token: OneShotToken,
        outcome: T,
    ) -> Result<TerminalReceipt<T>, OneShotError> {
        if token != self.token {
            return Err(OneShotError::StaleToken);
        }
        if self.terminal.is_some() {
            return Err(OneShotError::AlreadyTerminal);
        }
        self.terminal = Some(outcome);
        Ok(TerminalReceipt { token, outcome })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminalization_is_single_winner_and_failures_do_not_mutate() {
        let mut gate = OneShotGate::new(7, 3).unwrap();
        let token = gate.token();
        let receipt = gate.try_terminalize(token, 11_u8).unwrap();
        assert_eq!(receipt.outcome(), 11);
        let before = gate;
        assert_eq!(
            gate.try_terminalize(token, 12),
            Err(OneShotError::AlreadyTerminal)
        );
        assert_eq!(gate, before);
    }
}
