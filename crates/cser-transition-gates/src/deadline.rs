// SPDX-License-Identifier: MPL-2.0

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineToken {
    owner: u64,
    generation: u64,
    deadline: u64,
}

impl DeadlineToken {
    pub const fn owner(self) -> u64 {
        self.owner
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn deadline(self) -> u64 {
        self.deadline
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiryReceipt {
    token: DeadlineToken,
    observed_now: u64,
}

impl ExpiryReceipt {
    pub const fn token(self) -> DeadlineToken {
        self.token
    }

    pub const fn observed_now(self) -> u64 {
        self.observed_now
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineError {
    InvalidOwner,
    AlreadyArmed,
    NotArmed,
    StaleToken,
    TooEarly,
    CounterOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineProjection {
    pub owner: u64,
    pub next_generation: u64,
    pub current: Option<DeadlineToken>,
}

/// Generational arm/rearm/expire gate. An old token never names a replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineGate {
    owner: u64,
    next_generation: u64,
    current: Option<DeadlineToken>,
}

impl DeadlineGate {
    pub fn new(owner: u64) -> Result<Self, DeadlineError> {
        if owner == 0 {
            return Err(DeadlineError::InvalidOwner);
        }
        Ok(Self {
            owner,
            next_generation: 1,
            current: None,
        })
    }

    pub const fn projection(&self) -> DeadlineProjection {
        DeadlineProjection {
            owner: self.owner,
            next_generation: self.next_generation,
            current: self.current,
        }
    }

    pub const fn current(&self) -> Option<DeadlineToken> {
        self.current
    }

    pub fn arm(&mut self, deadline: u64) -> Result<DeadlineToken, DeadlineError> {
        if self.current.is_some() {
            return Err(DeadlineError::AlreadyArmed);
        }
        let generation = self.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(DeadlineError::CounterOverflow)?;
        let token = DeadlineToken {
            owner: self.owner,
            generation,
            deadline,
        };
        self.next_generation = next_generation;
        self.current = Some(token);
        Ok(token)
    }

    pub fn rearm(
        &mut self,
        current: DeadlineToken,
        deadline: u64,
    ) -> Result<DeadlineToken, DeadlineError> {
        self.validate(current)?;
        let generation = self.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(DeadlineError::CounterOverflow)?;
        let replacement = DeadlineToken {
            owner: self.owner,
            generation,
            deadline,
        };
        self.next_generation = next_generation;
        self.current = Some(replacement);
        Ok(replacement)
    }

    pub fn cancel(&mut self, current: DeadlineToken) -> Result<(), DeadlineError> {
        self.validate(current)?;
        self.current = None;
        Ok(())
    }

    pub fn expire(
        &mut self,
        presented: DeadlineToken,
        now: u64,
    ) -> Result<ExpiryReceipt, DeadlineError> {
        self.validate(presented)?;
        if now < presented.deadline {
            return Err(DeadlineError::TooEarly);
        }
        self.current = None;
        Ok(ExpiryReceipt {
            token: presented,
            observed_now: now,
        })
    }

    fn validate(&self, presented: DeadlineToken) -> Result<(), DeadlineError> {
        match self.current {
            None => Err(DeadlineError::NotArmed),
            Some(current) if current != presented => Err(DeadlineError::StaleToken),
            Some(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_deadline_is_stale_after_rearm() {
        let mut gate = DeadlineGate::new(9).unwrap();
        let old = gate.arm(10).unwrap();
        let current = gate.rearm(old, 20).unwrap();
        let before = gate;
        assert_eq!(gate.expire(old, u64::MAX), Err(DeadlineError::StaleToken));
        assert_eq!(gate, before);
        assert_eq!(gate.expire(current, 19), Err(DeadlineError::TooEarly));
        assert!(gate.expire(current, 20).is_ok());
    }
}
