// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod effect;
mod iommu_probe;
mod linux;
mod linux_pager;
mod pager;
mod scheduler;

use alloc::{boxed::Box, sync::Arc};

use effect::{EffectTimer, EffectToken, EffectWaiter};
use iommu_probe::{DmaQuiesceError, DmaQuiescer, Ostd018FailClosed};
use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{
        CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, Vaddr, VmIo, VmSpace,
    },
    power::{ExitCode, poweroff},
    prelude::*,
    task::{
        Task, TaskOptions, disable_preempt, inject_post_schedule_handler,
        scheduler as ostd_scheduler,
    },
    user::{ReturnReason, UserMode},
};
use scheduler::{CserScheduler, FIRST_FALLBACK_SELECTION_ATTEMPT, ProposalResult};

const AUTHORITY_EPOCH: u64 = 41;
const POLICY_LEASE_TICKS: u64 = 64;
const USER_TASK_ID: u64 = 100;
const FALLBACK_TASK_ID: u64 = 200;
pub(crate) const USER_MAP_ADDR: Vaddr = 0x0040_0000;
const EXPECTED_FAULT_ADDR: Vaddr = 0x0080_0000;
const FAULTING_LOAD_LEN: usize = 3;
const SYSCALL_PROBE: usize = 0x4353_4552;

pub struct TaskData {
    pub(crate) id: u64,
    pub(crate) vm_space: Option<Arc<VmSpace>>,
}

impl TaskData {
    pub(crate) fn new(id: u64, vm_space: Option<Arc<VmSpace>>) -> Self {
        Self { id, vm_space }
    }
}

#[ostd::main]
fn kernel_main() {
    let scheduler: &'static CserScheduler = Box::leak(Box::new(CserScheduler::new(
        AUTHORITY_EPOCH,
        POLICY_LEASE_TICKS,
    )));
    ostd_scheduler::inject_scheduler(scheduler);
    inject_post_schedule_handler(activate_current_task_vm);

    let binding = scheduler.binding();
    println!(
        "CSER Register authority_epoch={} binding_epoch={} effect=scheduler_policy",
        binding.authority_epoch, binding.binding_epoch,
    );

    let vm_space = Arc::new(create_vm_space(include_bytes!("../guest/probe.bin")));
    let user_vm_space = vm_space.clone();
    let user_task = Arc::new(
        TaskOptions::new(move || run_user_probe(user_vm_space, scheduler, binding))
            .data(TaskData::new(USER_TASK_ID, Some(vm_space)))
            .build()
            .unwrap(),
    );
    let fallback_task = Arc::new(
        TaskOptions::new(move || run_fallback_probe(scheduler, binding))
            .data(TaskData::new(FALLBACK_TASK_ID, None))
            .build()
            .unwrap(),
    );

    user_task.run();
    fallback_task.run();
    assert_eq!(
        scheduler.propose(binding, USER_TASK_ID),
        ProposalResult::Prepared
    );

    ostd_scheduler::enable_preemption_on_cpu();
    Task::yield_now();
    unreachable!("bootstrap context is not scheduled again");
}

fn activate_current_task_vm() {
    let Some(current) = Task::current() else {
        return;
    };
    let Some(data) = current.data().downcast_ref::<TaskData>() else {
        return;
    };
    if let Some(vm_space) = &data.vm_space {
        vm_space.activate();
    }
}

pub(crate) fn create_vm_space(program: &[u8]) -> VmSpace {
    let page_count = program.len().div_ceil(PAGE_SIZE);
    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .expect("allocate user probe pages");
    segment
        .write_bytes(0, program)
        .expect("copy user probe into frames");

    let vm_space = VmSpace::new();
    let guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(
            &guard,
            &(USER_MAP_ADDR..USER_MAP_ADDR + page_count * PAGE_SIZE),
        )
        .expect("create user mapping cursor");
    let property = PageProperty::new_user(PageFlags::RX, CachePolicy::Writeback);
    for frame in segment {
        cursor.map(frame.into(), property);
    }
    drop(cursor);
    vm_space
}

fn run_user_probe(
    vm_space: Arc<VmSpace>,
    scheduler: &'static CserScheduler,
    binding: scheduler::Binding,
) {
    vm_space.activate();
    let current = Task::current().expect("user probe runs in a task");
    let task_data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("user probe TaskData");
    assert!(
        task_data
            .vm_space
            .as_ref()
            .is_some_and(|vm| Arc::ptr_eq(vm, &vm_space))
    );

    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    let mut saw_syscall = false;
    let mut saw_page_fault = false;

    loop {
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => {
                assert_eq!(user_mode.context().rax(), SYSCALL_PROBE);
                saw_syscall = true;
                user_mode.context_mut().set_rax(0);
                println!(
                    "OSTD_PROBE UserMode return=UserSyscall VmSpace=active authority_epoch={}",
                    AUTHORITY_EPOCH,
                );
                assert_eq!(
                    scheduler.propose(binding, FALLBACK_TASK_ID),
                    ProposalResult::Prepared
                );
            }
            ReturnReason::UserException => {
                let exception = user_mode
                    .context_mut()
                    .take_exception()
                    .expect("UserException includes CpuException");
                match exception {
                    CpuException::PageFault(info) => {
                        assert_eq!(info.addr, EXPECTED_FAULT_ADDR);
                        saw_page_fault = true;
                        let resume = user_mode.context().rip() + FAULTING_LOAD_LEN;
                        user_mode.context_mut().set_rip(resume);
                        println!(
                            "OSTD_PROBE UserMode return=UserException exception=PageFault addr={:#x} authority_epoch={}",
                            info.addr, AUTHORITY_EPOCH,
                        );
                        assert!(saw_syscall, "policy crash follows its heartbeat/proposal");
                        scheduler.crash(binding, "user_exception_page_fault");
                    }
                    other => panic!("unexpected user exception: {other:?}"),
                }
            }
            ReturnReason::KernelEvent => {
                panic!("the probe does not request synthetic kernel events")
            }
        }

        if saw_syscall && saw_page_fault {
            println!(
                "OSTD_PROBE PASS api=UserMode+VmSpace syscall=true page_fault=true authority_epoch={}",
                AUTHORITY_EPOCH,
            );
            return;
        }
    }
}

fn run_fallback_probe(scheduler: &'static CserScheduler, old_binding: scheduler::Binding) {
    let evidence = scheduler
        .fallback_evidence()
        .expect("fallback selection records evidence");
    assert_eq!(evidence.pick_task_id, FALLBACK_TASK_ID);
    assert!(evidence.pick_tick >= evidence.crash_tick);
    assert_eq!(
        evidence.pick_selection_attempt,
        FIRST_FALLBACK_SELECTION_ATTEMPT
    );
    println!(
        "OSTD_PROBE PASS fallback_first_task={} fallback_first_selection_attempt={} observed_tick_delta={} tick_delta_diagnostic=true authority_epoch={} binding_epoch={}",
        evidence.pick_task_id,
        evidence.pick_selection_attempt,
        evidence.pick_tick - evidence.crash_tick,
        old_binding.authority_epoch,
        old_binding.binding_epoch + 1,
    );

    let crashed_binding = scheduler.binding();
    assert_eq!(crashed_binding.binding_epoch, old_binding.binding_epoch + 1);
    assert_eq!(
        scheduler.propose(crashed_binding, USER_TASK_ID),
        ProposalResult::RejectNoSupervisor
    );
    let wait_token = EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: 9,
        effect_id: 1,
    };
    println!(
        "CSER Register authority_epoch={} binding_epoch={} effect=wait effect_id={}",
        AUTHORITY_EPOCH, crashed_binding.binding_epoch, wait_token.effect_id,
    );
    let (waiter, waker) = EffectWaiter::new_pair(wait_token);
    assert_eq!(waiter.token(), wait_token);
    assert_eq!(waker.token(), wait_token);
    assert!(waker.wake_up());
    waiter.wait();

    let timer_token = EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: 9,
        effect_id: 2,
    };
    println!(
        "CSER Register authority_epoch={} binding_epoch={} effect=timer effect_id={}",
        AUTHORITY_EPOCH, crashed_binding.binding_epoch, timer_token.effect_id,
    );
    let timer = EffectTimer::after(timer_token, 1);
    assert_eq!(timer.token(), timer_token);
    assert!(timer.deadline() >= ostd::timer::Jiffies::elapsed().as_u64());
    let _ = timer.is_expired();
    println!(
        "OSTD_PROBE PASS wrappers=wait+timer carry_effect_token=true authority_epoch={}",
        AUTHORITY_EPOCH,
    );

    // Keep the scheduler in its kernel-owned FIFO fallback while pager tasks
    // block and wake one another. Pager service binding epochs are independent
    // from this scheduler-policy binding.
    pager::run_pager_slices();

    let linux_scheduler_binding = scheduler.rebind(AUTHORITY_EPOCH);
    assert_eq!(
        linux_scheduler_binding.binding_epoch,
        old_binding.binding_epoch + 1
    );

    // Linux compatibility is a bounded pressure test, not Nexus's native ABI.
    // Its policy first proposes the runnable guest under a shared workload
    // scope, then crashes in user mode and forces a fresh FIFO fallback pick.
    linux::run_linux_hello_slice(scheduler, linux_scheduler_binding);

    assert_eq!(
        scheduler.binding().binding_epoch,
        linux_scheduler_binding.binding_epoch + 1
    );
    assert_eq!(
        scheduler.propose(old_binding, USER_TASK_ID),
        ProposalResult::RejectStale
    );

    let dma_token = EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: 10,
        effect_id: 3,
    };
    assert_eq!(
        Ostd018FailClosed.unmap_invalidate_and_wait(dma_token),
        Err(DmaQuiesceError::IotlbInvalidationUnavailable)
    );
    println!(
        "IOMMU_PROBE PASS result=FAIL_CLOSED reason=IOTLB_INVALIDATION_UNAVAILABLE ostd=0.18.0 authority_epoch={}",
        AUTHORITY_EPOCH,
    );

    println!("SPIKE_RESULT PASS");
    poweroff(ExitCode::Success);
}
