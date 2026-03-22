use super::super::*;
use alloc::sync::Arc;

fn log_tty_bridge_packet(_prefix: &[u8], _key: u64) {}

fn log_port_packet(prefix: &[u8], packet: &zx_port_packet_t) {
    let _ = prefix;
    let _ = packet;
}

fn log_packet_loop_wait(prefix: &[u8], detail: u64) {
    let _ = prefix;
    let _ = detail;
}

impl StarnixKernel {
    fn service_tty_bridge_packet(&mut self, packet_key: u64) -> Result<(), zx_status_t> {
        log_tty_bridge_packet(b"tty-bridge: pkt ", packet_key);
        let Some((bridge, packet_kind)) = self.tty_bridge_packets.get(&packet_key).cloned() else {
            return Err(ZX_ERR_BAD_STATE);
        };
        if packet_kind {
            log_tty_bridge_packet(b"tty-bridge: svc-rx ", packet_key);
        } else {
            log_tty_bridge_packet(b"tty-bridge: svc-tx ", packet_key);
        }
        let closed = bridge.service(packet_kind)?;
        log_tty_bridge_packet(b"tty-bridge: done ", packet_key);
        if !closed {
            if packet_kind {
                log_tty_bridge_packet(b"tty-bridge: rearm-rx ", packet_key);
                bridge.arm_input(self.port, packet_key)?;
            } else {
                log_tty_bridge_packet(b"tty-bridge: rearm-tx ", packet_key);
                bridge.arm_output(self.port, packet_key)?;
            }
        } else {
            log_tty_bridge_packet(b"tty-bridge: closed ", packet_key);
            self.tty_bridge_packets
                .retain(|_, (registered, _)| !Arc::ptr_eq(registered, &bridge));
        }
        Ok(())
    }

    fn task_id_for_packet_key(&self, packet_key: u64) -> Option<i32> {
        self.tasks
            .iter()
            .find_map(|(tid, task)| (task.carrier.packet_key == packet_key).then_some(*tid))
    }

    fn waiting_task_id_for_packet_key(&self, packet_key: u64) -> Option<i32> {
        self.tasks.iter().find_map(|(tid, task)| match task.state {
            TaskState::Waiting(wait) if wait.packet_key() == Some(packet_key) => Some(*tid),
            TaskState::Running | TaskState::Waiting(_) => None,
        })
    }

    pub(in crate::starnix) fn run(&mut self) -> i32 {
        let mut stdout = Vec::new();
        loop {
            if let Some(status) = self.root_group_status() {
                return status;
            }
            let mut packet = zx_port_packet_t::default();
            log_packet_loop_wait(b"starnix-loop: wait ", self.port);
            let wait_status = zx_port_wait(self.port, AX_TIME_INFINITE, &mut packet);
            if wait_status != ZX_OK {
                return map_status_to_return_code(wait_status);
            }
            log_packet_loop_wait(b"starnix-loop: wake ", packet.key);
            log_port_packet(b"port-pkt: ", &packet);
            match packet.type_ {
                ZX_PKT_TYPE_USER => {
                    if self.tty_bridge_packets.contains_key(&packet.key) {
                        log_tty_bridge_packet(b"tty-bridge: user ", packet.key);
                    }
                    if packet.key == STARNIX_SIGNAL_WAKE_PACKET_KEY
                        && packet.user.u64[0] == STARNIX_WAIT_WAKE_KIND_SIGNAL
                    {
                        let task_id =
                            i32::try_from(packet.user.u64[1]).map_err(|_| ZX_ERR_BAD_STATE);
                        let Ok(task_id) = task_id else {
                            return map_status_to_return_code(ZX_ERR_BAD_STATE);
                        };
                        if let Err(status) = self.retry_waiting_task(task_id, &mut stdout) {
                            return map_status_to_return_code(status);
                        }
                        continue;
                    }
                    if let Some(task_id) = self.waiting_task_id_for_packet_key(packet.key) {
                        if let Err(status) = self.retry_waiting_task(task_id, &mut stdout) {
                            return map_status_to_return_code(status);
                        }
                        continue;
                    }
                    let Some(task_id) = self.task_id_for_packet_key(packet.key) else {
                        return map_status_to_return_code(ZX_ERR_BAD_STATE);
                    };
                    let reason = packet.user.u64[1] as u16;
                    if reason != AX_GUEST_STOP_REASON_X64_SYSCALL {
                        return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED);
                    }
                    let sidecar = self
                        .tasks
                        .get(&task_id)
                        .map(|task| task.carrier.sidecar_vmo);
                    let Some(sidecar) = sidecar else {
                        return map_status_to_return_code(ZX_ERR_BAD_STATE);
                    };
                    let mut stop_state = match ax_guest_stop_state_read(sidecar) {
                        Ok(stop_state) => stop_state,
                        Err(status) => return map_status_to_return_code(status),
                    };
                    let action = match self.handle_syscall(task_id, &mut stop_state, &mut stdout) {
                        Ok(action) => action,
                        Err(status) => return map_status_to_return_code(status),
                    };
                    if let Err(status) = self.complete_task_action(task_id, action, &mut stop_state)
                    {
                        return map_status_to_return_code(status);
                    }
                }
                ZX_PKT_TYPE_SIGNAL_ONE => {
                    if self.tty_bridge_packets.contains_key(&packet.key) {
                        log_tty_bridge_packet(b"tty-bridge: sig  ", packet.key);
                    }
                    if self.tty_bridge_packets.contains_key(&packet.key) {
                        if let Err(status) = self.service_tty_bridge_packet(packet.key) {
                            return map_status_to_return_code(status);
                        }
                        continue;
                    }
                    let Some(task_id) = self.waiting_task_id_for_packet_key(packet.key) else {
                        if let Some((epoll_key, target_key)) =
                            self.epoll_packets.get(&packet.key).copied()
                            && let Err(status) =
                                self.handle_epoll_ready_packet(epoll_key, target_key)
                        {
                            return map_status_to_return_code(status);
                        }
                        continue;
                    };
                    if let Err(status) = self.retry_waiting_task(task_id, &mut stdout) {
                        return map_status_to_return_code(status);
                    }
                }
                _ => return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED),
            }
        }
    }

    fn root_group_status(&self) -> Option<i32> {
        self.groups
            .get(&self.root_tgid)
            .and_then(|group| match group.state {
                ThreadGroupState::Zombie { exit_code, .. } => Some(exit_code),
                ThreadGroupState::Running | ThreadGroupState::Stopped => None,
            })
    }
}
