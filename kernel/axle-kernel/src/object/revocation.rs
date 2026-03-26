use super::*;

fn cancel_revoked_timers(
    state: &KernelState,
    group: axle_core::RevocationGroupId,
    generation: u64,
    current_epoch: u64,
) -> Result<(), zx_status_t> {
    let revoked = state.with_objects(|objects| {
        Ok(objects
            .iter()
            .filter_map(|(object_key, object)| match object {
                KernelObject::Timer(timer)
                    if timer.armed_revocation.contains_revoked(
                        group,
                        generation,
                        current_epoch,
                    ) =>
                {
                    Some((object_key, timer.timer_id))
                }
                _ => None,
            })
            .collect::<Vec<_>>())
    })?;

    for (object_key, timer_id) in revoked {
        state.with_kernel_mut(|kernel| {
            kernel
                .cancel_timer_object(timer_id)
                .map_err(map_timer_error)
        })?;
        state.with_objects_mut(|objects| {
            let timer = match objects.get_mut(object_key) {
                Some(KernelObject::Timer(timer)) => timer,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            timer.armed_revocation = RevocationSet::none();
            Ok(())
        })?;
    }
    Ok(())
}

fn purge_revoked_port_packets(
    state: &KernelState,
    group: axle_core::RevocationGroupId,
    generation: u64,
    current_epoch: u64,
) -> Result<(), zx_status_t> {
    let port_keys = state.with_objects(|objects| {
        Ok(objects
            .iter()
            .filter_map(|(object_key, object)| match object {
                KernelObject::Port(_) => Some(object_key),
                _ => None,
            })
            .collect::<Vec<_>>())
    })?;

    for port_key in port_keys {
        let removed = state.with_objects_mut(|objects| {
            let port = match objects.get_mut(port_key) {
                Some(KernelObject::Port(port)) => port,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            Ok(port.retain_kernel_packets(|packet| {
                !packet
                    .revocation
                    .contains_revoked(group, generation, current_epoch)
            }))
        });
        match removed {
            Ok(0) => {}
            Ok(_) => {
                let current = signals_for_object_id(state, port_key)?;
                crate::wait::publish_signals_changed(state, port_key, current)?;
            }
            Err(ZX_ERR_BAD_HANDLE) => {}
            Err(status) => return Err(status),
        }
    }
    Ok(())
}

pub fn create_revocation_group(options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let job_id = state.current_job_id()?;
        state.quota_check_and_increment(job_id, ObjectKindTag::RevocationGroup)?;

        let result = (|| {
            let token = state.with_core_mut(|kernel| Ok(kernel.create_revocation_group()))?;
            let object_id = state.alloc_object_id();
            state.with_objects_mut(|objects| {
                objects.insert(
                    object_id,
                    KernelObject::RevocationGroup(RevocationGroupObject { token }),
                )?;
                Ok(())
            })?;
            state.alloc_handle_for_object(object_id, handle::revocation_group_default_rights())
        })();

        if result.is_err() {
            state.quota_decrement(job_id, ObjectKindTag::RevocationGroup);
        }
        result
    })
}

pub fn revocation_group_get_info(
    handle: zx_handle_t,
) -> Result<axle_types::ax_revocation_group_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        let token = state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::RevocationGroup(group)) => Ok(group.token()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })?;
        let epoch = state.with_core(|kernel| kernel.revocation_group_epoch(token))?;
        Ok(axle_types::ax_revocation_group_info_t {
            group_id: token.id().raw(),
            generation: token.generation() as u32,
            epoch: epoch as u32,
            reserved0: 0,
        })
    })
}

pub fn revocation_group_revoke(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let token = state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::RevocationGroup(group)) => Ok(group.token()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })?;
        let current_epoch =
            state.with_core_mut(|kernel| kernel.revoke_group_and_get_epoch(token))?;
        state.with_kernel_mut(|kernel| {
            let _ = kernel.cancel_revoked_blocking_waits(
                token.id(),
                token.generation(),
                current_epoch,
            )?;
            Ok(())
        })?;
        cancel_revoked_timers(state, token.id(), token.generation(), current_epoch)?;
        state.with_reactor_mut(|reactor| {
            reactor.remove_revoked_wait_async(token.id(), token.generation(), current_epoch);
            Ok(())
        })?;
        purge_revoked_port_packets(state, token.id(), token.generation(), current_epoch)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port_queue::KernelPort;

    fn revocation_fixture(
        state: &KernelState,
    ) -> (
        axle_core::RevocationGroupToken,
        axle_core::RevocationRef,
        axle_core::RevocationGroupToken,
        axle_core::RevocationRef,
    ) {
        state
            .with_core_mut_for_tests(|kernel| {
                let live_token = kernel.create_revocation_group();
                let live_ref = kernel.snapshot_revocation_ref(live_token)?;
                let revoked_token = kernel.create_revocation_group();
                let revoked_ref = kernel.snapshot_revocation_ref(revoked_token)?;
                Ok((live_token, live_ref, revoked_token, revoked_ref))
            })
            .expect("revocation fixture")
    }

    #[test]
    fn cancel_revoked_timers_disarms_future_deadlines() {
        let state = KernelState::new_for_tests();
        let (_live_token, _live_ref, revoked_token, revoked_ref) = revocation_fixture(&state);
        let timer_id = state
            .with_kernel_mut(|kernel| Ok(kernel.create_timer_object()))
            .expect("create timer");
        let timer_key = state.alloc_object_id();
        state
            .with_registry_mut(|registry| {
                registry.insert(
                    timer_key,
                    KernelObject::Timer(TimerObject {
                        timer_id,
                        armed_revocation: RevocationSet::one(Some(revoked_ref)),
                    }),
                )?;
                Ok(())
            })
            .expect("insert timer object");
        state
            .with_kernel_mut(|kernel| {
                kernel
                    .set_timer_object(timer_id, 100, 0)
                    .map_err(map_timer_error)
            })
            .expect("arm timer");

        let current_epoch = state
            .with_core_mut_for_tests(|kernel| kernel.revoke_group_and_get_epoch(revoked_token))
            .expect("revoke group");
        cancel_revoked_timers(
            &state,
            revoked_token.id(),
            revoked_token.generation(),
            current_epoch,
        )
        .expect("cancel revoked timers");

        state
            .with_objects(|objects| {
                let timer = match objects.get(timer_key) {
                    Some(KernelObject::Timer(timer)) => timer,
                    other => panic!("unexpected timer object: {other:?}"),
                };
                assert_eq!(timer.armed_revocation, RevocationSet::none());
                Ok(())
            })
            .expect("timer object lookup");
        let event_count = state
            .with_kernel_mut(|kernel| Ok(kernel.poll_reactor(200).into_events().len()))
            .expect("poll reactor");
        assert_eq!(event_count, 0);
    }

    #[test]
    fn purge_revoked_port_packets_keeps_user_and_live_control_packets() {
        let state = KernelState::new_for_tests();
        let (_live_token, live_ref, revoked_token, revoked_ref) = revocation_fixture(&state);
        let port = state
            .with_kernel_mut(|kernel| KernelPort::new(kernel, PORT_CAPACITY, PORT_KERNEL_RESERVE))
            .expect("create port");
        let port_key = state.alloc_object_id();
        state
            .with_registry_mut(|registry| {
                registry.insert(port_key, KernelObject::Port(port))?;
                Ok(())
            })
            .expect("insert port");
        state
            .with_objects_mut(|objects| {
                let port = match objects.get_mut(port_key) {
                    Some(KernelObject::Port(port)) => port,
                    other => panic!("unexpected port object: {other:?}"),
                };
                port.queue_user(axle_core::Packet::user(11))
                    .map_err(map_port_error)?;
                port.queue_kernel(axle_core::Packet::signal_with_revocation(
                    1,
                    10.into(),
                    Signals::CHANNEL_READABLE,
                    Signals::CHANNEL_READABLE,
                    1,
                    10,
                    RevocationSet::one(Some(live_ref)),
                ))
                .map_err(map_port_error)?;
                port.queue_kernel(axle_core::Packet::signal_with_revocation(
                    2,
                    20.into(),
                    Signals::CHANNEL_READABLE,
                    Signals::CHANNEL_READABLE,
                    1,
                    20,
                    RevocationSet::one(Some(revoked_ref)),
                ))
                .map_err(map_port_error)?;
                Ok(())
            })
            .expect("seed port packets");

        let current_epoch = state
            .with_core_mut_for_tests(|kernel| kernel.revoke_group_and_get_epoch(revoked_token))
            .expect("revoke group");
        purge_revoked_port_packets(
            &state,
            revoked_token.id(),
            revoked_token.generation(),
            current_epoch,
        )
        .expect("purge revoked packets");

        state
            .with_objects_mut(|objects| {
                let port = match objects.get_mut(port_key) {
                    Some(KernelObject::Port(port)) => port,
                    other => panic!("unexpected port object: {other:?}"),
                };
                let first = port.pop().map_err(map_port_error)?;
                assert_eq!(first.kind, axle_core::PacketKind::User);
                let second = port.pop().map_err(map_port_error)?;
                assert_eq!(second.kind, axle_core::PacketKind::Signal);
                assert_eq!(second.key, 1);
                assert_eq!(port.signals(), Signals::NONE);
                Ok(())
            })
            .expect("inspect retained port packets");
    }
}
