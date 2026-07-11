// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use ostd::{
    sync::{Waiter, Waker},
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
        self.inner.wake_up()
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
