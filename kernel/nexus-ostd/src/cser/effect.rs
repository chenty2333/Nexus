// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use cser_transition_gates::oneshot::OneShotGate;
use ostd::{
    sync::{SpinLock, Waiter, Waker},
    timer::Jiffies,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectToken {
    pub authority_epoch: u64,
    pub scope_id: u64,
    pub effect_id: u64,
}

pub struct EffectWaiter {
    token: EffectToken,
    inner: Waiter,
}

pub struct EffectWaker {
    token: EffectToken,
    inner: Arc<Waker>,
    wake_gate: SpinLock<OneShotGate<WakeOutcome>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WakeOutcome {
    Published,
}

impl EffectWaiter {
    pub fn new_pair(token: EffectToken) -> (Self, EffectWaker) {
        let (waiter, waker) = Waiter::new_pair();
        (
            Self {
                token,
                inner: waiter,
            },
            EffectWaker {
                token,
                inner: waker,
                wake_gate: SpinLock::new(
                    OneShotGate::new(token.effect_id, token.authority_epoch)
                        .expect("effect continuation identity must be nonzero"),
                ),
            },
        )
    }

    pub fn token(&self) -> EffectToken {
        self.token
    }

    pub fn wait(&self) {
        self.inner.wait();
    }
}

impl EffectWaker {
    pub fn token(&self) -> EffectToken {
        self.token
    }

    pub fn wake_up(&self) -> bool {
        let mut gate = self.wake_gate.lock();
        if gate.terminal().is_some() {
            return false;
        }
        let published = self.inner.wake_up();
        if published {
            let token = gate.token();
            gate.try_terminalize(token, WakeOutcome::Published)
                .expect("the checked effect continuation has exactly one winner");
        }
        published
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectTimer {
    token: EffectToken,
    deadline: u64,
}

impl EffectTimer {
    pub fn after(token: EffectToken, ticks: u64) -> Self {
        Self {
            token,
            deadline: Jiffies::elapsed().as_u64().saturating_add(ticks),
        }
    }

    pub fn token(&self) -> EffectToken {
        self.token
    }

    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    pub fn is_expired(&self) -> bool {
        Jiffies::elapsed().as_u64() >= self.deadline
    }
}
