use super::*;

impl Kernel {
    fn prepare_thread_activation_on_current_cpu(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<CpuThreadActivation, zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let activation_now_ns = self.current_cpu_now_ns().max(0) as u64;
        let previous_thread_id = self.current_cpu_scheduler()?.current_thread_id;
        let previous_address_space_id = if let Some(previous_thread_id) = previous_thread_id {
            if let Some(previous_thread) = self.threads.get_mut(&previous_thread_id) {
                previous_thread.running_on_cpu = None;
            }
            let process_id = self
                .threads
                .get(&previous_thread_id)
                .ok_or(ZX_ERR_BAD_STATE)?
                .process_id;
            Some(self.process(process_id)?.address_space_id)
        } else {
            None
        };
        let next_process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .process_id;
        let next_address_space_id = self.process(next_process_id)?.address_space_id;
        let context = self
            .threads
            .get_mut(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .context
            .ok_or(ZX_ERR_BAD_STATE)?;
        self.current_cpu_scheduler_mut().current_thread_id = Some(thread_id);
        self.arm_current_slice_from(self.current_cpu_now_ns());
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if let (Some(enqueued_ns), Some(source_cpu_id), Some(target_cpu_id)) = (
            thread.remote_wake_enqueued_ns,
            thread.remote_wake_source_cpu,
            thread.remote_wake_target_cpu,
        ) {
            if target_cpu_id == current_cpu_id {
                crate::trace::record_remote_wake_latency(
                    thread_id,
                    source_cpu_id,
                    target_cpu_id,
                    activation_now_ns.saturating_sub(enqueued_ns),
                );
            }
        }
        thread.remote_wake_enqueued_ns = None;
        thread.remote_wake_source_cpu = None;
        thread.remote_wake_target_cpu = None;
        thread.running_on_cpu = Some(current_cpu_id);
        thread.last_cpu = current_cpu_id;
        Ok(CpuThreadActivation {
            previous_thread_id,
            thread_id,
            previous_address_space_id,
            next_address_space_id,
            current_cpu_id,
            context,
        })
    }

    fn activate_thread_on_current_cpu(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<UserContext, zx_status_t> {
        let activation = self.prepare_thread_activation_on_current_cpu(thread_id)?;
        let switch_kind = self.with_vm_mut(|vm| {
            vm.activate_cpu_address_space_transition(
                activation.current_cpu_id(),
                activation.previous_address_space_id(),
                activation.next_address_space_id(),
            )
        })?;
        crate::trace::record_context_switch(
            activation.previous_thread_id(),
            activation.thread_id(),
            activation.address_space_switched(),
        );
        crate::trace::record_tlb_address_space_switch(
            activation.previous_address_space_id().unwrap_or(0),
            activation.next_address_space_id(),
            switch_kind,
        );
        Ok(activation.context())
    }

    pub(crate) fn take_current_cpu_idle_activation(
        &mut self,
    ) -> Result<Option<CpuThreadActivation>, zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        self.mark_cpu_online(current_cpu_id);
        if self.current_cpu_scheduler()?.current_thread_id.is_some() {
            return Err(ZX_ERR_BAD_STATE);
        }
        let _ = self.take_reschedule_requested(current_cpu_id);
        let Some(thread_id) = self.take_next_runnable_thread_for_current_cpu() else {
            return Ok(None);
        };
        let activation = self.prepare_thread_activation_on_current_cpu(thread_id)?;
        self.restore_thread_fpu_state(thread_id)?;
        Ok(Some(activation))
    }

    pub(crate) fn switch_to_thread(
        &mut self,
        thread_id: ThreadId,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        let context = self.activate_thread_on_current_cpu(thread_id)?;
        self.restore_thread_fpu_state(thread_id)?;
        context.restore(trap, cpu_frame)?;
        Ok(())
    }

    fn restore_thread_fpu_state(&self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        crate::arch::fpu::restore_current(&thread.fpu_state);
        Ok(())
    }
}
