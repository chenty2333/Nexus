#!/usr/bin/env bash
set -euo pipefail

log=${1:?usage: assert-serial.sh SERIAL_LOG}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# FallbackPick records are deliberately omitted from this total-order list.
# Once Crash switches the gate to fallback, the outgoing user task and the
# newly runnable task can print their diagnostic records in either order.  The
# trace oracle below checks the semantic Crash -> first-pick partial order.
patterns=(
    "CSER Register authority_epoch=41 binding_epoch=1 effect=scheduler_policy"
    "CSER Prepare authority_epoch=41 binding_epoch=1 proposal_task=100"
    "CSER Commit authority_epoch=41 binding_epoch=1 proposal_task=100 state=Committed"
    "OSTD_PROBE UserMode return=UserSyscall VmSpace=active authority_epoch=41"
    "CSER Prepare authority_epoch=41 binding_epoch=1 proposal_task=200"
    "OSTD_PROBE UserMode return=UserException exception=PageFault addr=0x800000 authority_epoch=41"
    "CSER Crash authority_epoch=41 previous_binding_epoch=1 binding_epoch=2"
    "OSTD_PROBE PASS api=UserMode+VmSpace syscall=true page_fault=true authority_epoch=41"
    "OSTD_PROBE PASS fallback_first_task=200 fallback_first_selection_attempt=1 observed_tick_delta="
    "CSER REJECT_NO_SUPERVISOR action=Prepare authority_epoch=41 binding_epoch=2 proposal_task=100"
    "OSTD_PROBE PASS wrappers=wait+timer carry_effect_token=true authority_epoch=41"
    "EFFECT_REGISTRY PASS effects=2 recovery_adoptions=2 committed_drains=1 uncommitted_aborts=1 publication_acks=2 stale_authority_rejected=true quiescent=true"
    "READINESS_CORE PASS sample_arm=atomic edge_deliveries=2 level_deliveries=2 oneshot_deliveries=1 immediate_deliveries=1 stale_source_rejected=true stale_subscription_rejected=true duplicate_publication_rejected=true"
    "PAGER_SCENARIO BEGIN scenario=recover scope=20 fault=1 scheduler_mode=kernel_fifo_fallback"
    "PAGER Register scenario=recover scope=20 fault=1 authority_epoch=71 binding_epoch=1 as=1 as_generation=1 thread=300 addr=0x401000 access_bits=0x4 rip=0x400005"
    "PAGER PrepareZero scenario=recover fault=1 binding_epoch=1 owner=kernel credit=Held"
    "PAGER Crash scenario=recover supervisor=301 previous_binding_epoch=1 binding_epoch=2"
    "PAGER REJECT_STALE scenario=recover stage=post_crash action=Commit proposal_binding_epoch=1 current_binding_epoch=2 vm_mutation=false"
    "PAGER Fallback scenario=recover binding_epoch=2 action=close_reply_gate+retain+watchdog"
    "PAGER FreshSpawn scenario=recover task=303 vm=fresh user_mode=constructed_in_task binding_epoch=2"
    "PAGER RecoverySnapshot scenario=recover replacement=303 binding_epoch=2 fault=1 phase=Prepared prepared=true"
    "PAGER Ready scenario=recover replacement=303 binding_epoch=2"
    "PAGER REJECT_NO_SUPERVISOR scenario=recover stage=pre_rebind action=Commit proposal_binding_epoch=2 vm_mutation=false"
    "PAGER Rebind scenario=recover replacement=303 binding_epoch=2 epoch_advanced=false pager_fallback=Standby"
    "PAGER REJECT_STALE scenario=recover stage=post_rebind action=Commit proposal_binding_epoch=1 current_binding_epoch=2 vm_mutation=false"
    "PAGER RecoverNext scenario=recover replacement=303 fault=1 old_binding_epoch=1 phase=Prepared"
    "PAGER Adopt scenario=recover replacement=303 fault=1 old_binding_epoch=1 binding_epoch=2 explicit=true"
    "PAGER Commit scenario=recover replacement=303 fault=1 binding_epoch=2 pte_published=true credit=Spent"
    "PAGER TlbSync scenario=recover fault=1 issue=true dispatch=true synchronize=true cpu=local"
    "PAGER Complete scenario=recover fault=1 terminal=Completed wake=one-shot"
    "PAGER ClientResume scenario=recover fault=1 same_rip=true value=0 terminal=Resolved"
    "PAGER_SCENARIO PASS scenario=recover terminalizations=1"
    "PAGER_SCENARIO BEGIN scenario=timeout scope=21 fault=2 scheduler_mode=kernel_fifo_fallback"
    "PAGER Register scenario=timeout scope=21 fault=2 authority_epoch=71 binding_epoch=1 as=1 as_generation=1 thread=310 addr=0x401000 access_bits=0x4 rip=0x400005"
    "PAGER PrepareZero scenario=timeout fault=2 binding_epoch=1 owner=kernel credit=Held"
    "PAGER Crash scenario=timeout supervisor=311 previous_binding_epoch=1 binding_epoch=2"
    "PAGER REJECT_STALE scenario=timeout stage=post_crash action=Commit proposal_binding_epoch=1 current_binding_epoch=2 vm_mutation=false"
    "PAGER WatchdogArm scenario=timeout binding_epoch=2"
    "PAGER RevokeBegin scenario=timeout scope=21 old_authority_epoch=71 authority_epoch=72 reason=watchdog_timeout scope_phase=Closing reply_gate=closed cleanup_inflight=true wake_pending=true credit=Held"
    "PAGER CleanupDrop scenario=timeout fault=2 prepared_dropped=true outside_lock=true cleanup_inflight=true wake_pending=true credit=Held"
    "PAGER Abort scenario=timeout fault=2 terminal=Aborted prepared_dropped=true credit=Held cleanup_inflight=true wake_pending=true wake_published=true waker_dropped=true"
    "PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=false wake_pending=false wake_published=true waker_dropped=true credit=Returned pager_fallback=Standby"
    "PAGER ClientExit scenario=timeout fault=2 terminal=Aborted cooperative=true"
    "PAGER_SCENARIO PASS scenario=timeout terminalizations=1"
    "PAGER_SLICE PASS scenarios=recover+timeout single_cpu=true zero_page=true single_client=true task_kill=false"
    "CSER Rebind authority_epoch=41 binding_epoch=2"
    "LINUX_ELF MapPlan workload=linux-hello vaddr=0x400000"
    "LINUX_ELF MapPlan workload=linux-hello vaddr=0x401000"
    "publication=lazy-file-backed"
    "LINUX_ELF MapPlan workload=linux-hello vaddr=0x402000"
    "LINUX_ELF InitialStack workload=linux-hello"
    "argc=1 argv=1 envp=0 auxv=9 aligned16=true rw=true executable=false"
    "LINUX_ELF Loaded workload=linux-hello parser=object-0.39.1 format=ELF64 type=ET_EXEC arch=x86_64 static=true"
    "entry_publication=lazy-file-backed"
    "wx=false overlap=false"
    "LINUX_SLICE BEGIN workload=linux-hello format=ELF64 type=ET_EXEC"
    "scheduler_mode=user_policy_then_kernel_fifo_fallback scheduler_binding_epoch=2"
    "LINUX_CODE_PAGER Start workload=linux-hello effect=3 authority_epoch=91 scope=30"
    "CSER Prepare authority_epoch=41 binding_epoch=2 proposal_task=404"
    "CSER Commit authority_epoch=41 binding_epoch=2 proposal_task=404 state=Committed"
    "LINUX_SCHEDULER Register workload=linux-hello policy=404 workload_authority_epoch=91 scope=30 effect=0 scheduler_binding_epoch=2"
    "CSER PrepareScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=2 workload_authority_epoch=91 scope=30 effect=0 proposal_task=400"
    "CSER Crash authority_epoch=41 previous_binding_epoch=2 binding_epoch=3"
    "reason=linux_scheduler_policy_user_page_fault"
    "CSER CrashScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=3 workload_authority_epoch=91 scope=30 effect=0 pending_scoped_cleared=true fallback=kernel_fifo"
    "LINUX_SCHEDULER_POLICY EXIT workload=linux-hello policy=404 reason=real_user_page_fault guest_proposal_committed=false"
    "LINUX_CODE_PAGER Register workload=linux-hello effect=3 authority_epoch=91 scope=30 binding_epoch=1 thread=400"
    "access_bits=0x14 backing=elf-image"
    "LINUX_CODE_PAGER GuestBlocked workload=linux-hello effect=3 thread=400"
    "LINUX_CODE_PAGER PrepareImage workload=linux-hello effect=3 binding_epoch=1 bytes=4096"
    "owner=kernel pte_published=false"
    "LINUX_CODE_PAGER Crash workload=linux-hello supervisor=410 previous_binding_epoch=1 binding_epoch=2"
    "image_frame_retained=true pte_published=false"
    "LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_crash action=MapAndWake effect=3"
    "LINUX_CODE_PAGER Fallback workload=linux-hello binding_epoch=2"
    "LINUX_CODE_PAGER FreshSpawn workload=linux-hello task=412 vm=fresh user_mode=constructed_in_task binding_epoch=2"
    "LINUX_CODE_PAGER RecoverySnapshot workload=linux-hello replacement=412 binding_epoch=2 effect=3 phase=Prepared image_frame=true"
    "LINUX_CODE_PAGER Ready workload=linux-hello replacement=412 binding_epoch=2"
    "LINUX_CODE_PAGER REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind action=MapAndWake effect=3"
    "LINUX_CODE_PAGER Rebind workload=linux-hello replacement=412 binding_epoch=2"
    "LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_rebind action=MapAndWake effect=3"
    "LINUX_CODE_PAGER RecoverNext workload=linux-hello replacement=412 effect=3 old_binding_epoch=1 phase=Prepared"
    "LINUX_CODE_PAGER Adopt workload=linux-hello replacement=412 effect=3 old_binding_epoch=1 binding_epoch=2 explicit=true"
    "LINUX_CODE_PAGER Commit workload=linux-hello replacement=412 effect=3 binding_epoch=2 backing=elf-image"
    "permissions=RX pte_published=true"
    "LINUX_CODE_PAGER TlbSync workload=linux-hello effect=3 issue=true dispatch=true synchronize=true cpu=local single_cpu=true"
    "LINUX_CODE_PAGER Complete workload=linux-hello effect=3 terminal=Completed wake=one-shot pte=RX same_rip=true"
    "LINUX_CODE_PAGER GuestResume workload=linux-hello effect=3 thread=400"
    "same_rip=true resume_returns=1"
    "LINUX_SYSCALL Capture workload=linux-hello effect=1 kind=write nr=1 fd=1"
    "authority_epoch=91 binding_epoch=1"
    "LINUX_PORTAL Deliver workload=linux-hello personality=401 effect=1 binding_epoch=1 immutable_snapshot=true guest_context_writable=false"
    "LINUX_PERSONALITY Dispatch workload=linux-hello personality=401 kind=write nr=1 user_mode=true uapi=linux-raw-sys-0.12.1"
    "LINUX_SYSCALL Prepare workload=linux-hello effect=1 kind=write binding_epoch=1 guest_bytes_copied=23 owner=kernel"
    "LINUX_GUEST stdout=hello from linux-hello"
    "LINUX_SYSCALL BackendCommit workload=linux-hello personality=401 effect=1 kind=write binding_epoch=1 result=Committed output_publications=1 guest_reply_pending=true"
    "LINUX_PORTAL Queue workload=linux-hello sender=401 action=Reply effect=1 authority_epoch=91 scope=30 task=400 operation=1 binding_epoch=1 delivery=after_crash"
    "LINUX_PERSONALITY Crash workload=linux-hello supervisor=401 previous_binding_epoch=1 binding_epoch=2 reason=user_page_fault backend_committed=true guest_reply_pending=true"
    "LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_crash action=Reply effect=1"
    "LINUX_PORTAL Projection action=post_crash sender=401 opcode=0x4c520002 authority_epoch=91 scope=30 effect=1 task=400 operation=1 binding_epoch=1 result=StaleBinding mutation=false"
    "LINUX_PERSONALITY Fallback workload=linux-hello binding_epoch=2"
    "LINUX_PERSONALITY FreshSpawn workload=linux-hello task=403 vm=fresh user_mode=constructed_in_task binding_epoch=2"
    "LINUX_PERSONALITY RecoverySnapshot workload=linux-hello replacement=403 binding_epoch=2 effect=1 phase=BackendCommitted output_obligation=retained guest_reply_pending=true"
    "LINUX_PERSONALITY Ready workload=linux-hello replacement=403 binding_epoch=2"
    "LINUX_SYSCALL REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind action=Reply effect=1"
    "LINUX_PERSONALITY Rebind workload=linux-hello replacement=403 binding_epoch=2"
    "LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_rebind action=Reply effect=1"
    "LINUX_SYSCALL RecoverNext workload=linux-hello replacement=403 effect=1 old_binding_epoch=1 phase=BackendCommitted"
    "LINUX_PERSONALITY Dispatch workload=linux-hello personality=403 kind=write nr=1 user_mode=true recovered=true uapi=linux-raw-sys-0.12.1"
    "LINUX_SYSCALL Adopt workload=linux-hello replacement=403 effect=1 old_binding_epoch=1 binding_epoch=2 explicit=true"
    "LINUX_SYSCALL BackendCommit workload=linux-hello personality=403 effect=1 kind=write binding_epoch=2 result=AlreadyCommitted output_publications=1 guest_reply_pending=true"
    "LINUX_SYSCALL Reply workload=linux-hello replacement=403 effect=1 kind=write binding_epoch=2 backend_replayed=false guest_resume=one-shot terminal=Completed"
    "LINUX_SYSCALL Capture workload=linux-hello effect=2 kind=exit_group nr=231 status=0 authority_epoch=91 binding_epoch=2"
    "LINUX_PORTAL Deliver workload=linux-hello personality=403 effect=2 binding_epoch=2 immutable_snapshot=true guest_context_writable=false"
    "LINUX_PERSONALITY Dispatch workload=linux-hello personality=403 kind=exit_group nr=231 user_mode=true uapi=linux-raw-sys-0.12.1"
    "LINUX_SYSCALL Commit workload=linux-hello replacement=403 effect=2 kind=exit_group binding_epoch=2 terminal=Completed"
    "LINUX_GUEST Exit workload=linux-hello status=0 resumed_after_exit=false terminal=Exited"
    "LINUX_SCHEDULER PASS workload=linux-hello policy=404 fallback_first_task=400 fallback_first_selection_attempt=1 observed_tick_delta="
    "LINUX_CODE_PAGER PASS workload=linux-hello effect=3 backing=elf-image pager_crash_rebind=true old_binding_rejections=2 terminalizations=1 wake_publications=1 resume_returns=1 permissions=RX same_rip=true single_cpu=true bounded=true"
    "LINUX_SLICE PASS workload=linux-hello write=true exit_group=true personality_crash_rebind=true stale_reply_fenced=true terminalizations=2 output_publications=1"
    "CSER Rebind authority_epoch=41 binding_epoch=3"
    "LINUX_FUTEX_SLICE BEGIN scenarios=recover+expire scheduler_binding_epoch=3 bounded=true unified_registry=false smp=1"
    "LINUX_FUTEX_SCENARIO BEGIN scenario=recover authority_epoch=101 scope=40 asid=600 generation=1 address=0x401000 waiter=500 waker=501 shared_vm=true smp=1 scheduler_mode=user_policy_then_kernel_fifo_fallback"
    "CSER Prepare authority_epoch=41 binding_epoch=3 proposal_task=505"
    "CSER Commit authority_epoch=41 binding_epoch=3 proposal_task=505 state=Committed"
    "LINUX_FUTEX_SCHEDULER Register scenario=recover policy=505 workload_authority_epoch=101 scope=40 effect=1 scheduler_binding_epoch=3"
    "CSER PrepareScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=3 workload_authority_epoch=101 scope=40 effect=1 proposal_task=500"
    "CSER Crash authority_epoch=41 previous_binding_epoch=3 binding_epoch=4"
    "CSER CrashScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=4 workload_authority_epoch=101 scope=40 effect=1 pending_scoped_cleared=true fallback=kernel_fifo"
    "LINUX_FUTEX_SCHEDULER_POLICY EXIT scenario=recover policy=505 reason=real_user_page_fault waiter_proposal_committed=false"
    "LINUX_FUTEX Mismatch scenario=recover observed=0 expected=1 result=EAGAIN effect_created=false wait_credit_held=false mutation=false"
    "LINUX_FUTEX PortalResult scenario=recover action=WaitRegister sender=502 opcode=0x4c600002 authority_epoch=101 scope=40 effect=1 task=500 operation=1 address_space=600 generation=1 address=0x401000 binding_epoch=1 result=Applied mutation=true"
    "LINUX_FUTEX WaitRegister scenario=recover observed=0 expected=0 atomic=true queue=1 wait_credit=Held vm_restored=true"
    "LINUX_FUTEX Crash scenario=recover personality=502 previous_binding_epoch=1 binding_epoch=2 reason=real_user_page_fault fallback=kernel watchdog=armed cohort=1"
    "LINUX_FUTEX Fallback scenario=recover binding_epoch=2 action=close_portal_gate+retain_queue+watchdog"
    "LINUX_FUTEX FreshSpawn scenario=recover task=504 vm=fresh user_mode=constructed_in_task binding_epoch=2"
    "LINUX_FUTEX PortalResult scenario=recover action=Snapshot sender=504 opcode=0x4c600010"
    "LINUX_FUTEX PortalResult scenario=recover action=Ready sender=504 opcode=0x4c600011"
    "LINUX_FUTEX PortalResult scenario=recover action=WaitRegister sender=504 opcode=0x4c600002 authority_epoch=101 scope=40 effect=1 task=500 operation=1 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=NoSupervisor mutation=false"
    "LINUX_FUTEX PortalResult scenario=recover action=Rebind sender=504 opcode=0x4c600012"
    "LINUX_FUTEX PortalResult scenario=recover action=WaitRegister sender=504 opcode=0x4c600002 authority_epoch=101 scope=40 effect=1 task=500 operation=1 address_space=600 generation=1 address=0x401000 binding_epoch=1 result=StaleBinding mutation=false"
    "LINUX_FUTEX PortalResult scenario=recover action=RecoverNext sender=504 opcode=0x4c600013"
    "LINUX_FUTEX PortalResult scenario=recover action=Adopt sender=504 opcode=0x4c600014 authority_epoch=101 scope=40 effect=1 task=500 operation=1 address_space=600 generation=1 address=0x401000 binding_epoch=1 result=Applied mutation=true"
    "LINUX_FUTEX WatchdogCancel scenario=recover effect=1 binding_epoch=2 timer_credit=Free queued_wait_retained=true"
    "LINUX_FUTEX PortalResult scenario=recover action=Adopt sender=504 opcode=0x4c600014 authority_epoch=101 scope=40 effect=999 task=500 operation=1 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=IdentityMismatch mutation=false"
    "LINUX_FUTEX PortalResult scenario=recover action=Adopt sender=504 opcode=0x4c600014 authority_epoch=101 scope=40 effect=1 task=500 operation=1 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=NotAdoptable mutation=false"
    "LINUX_FUTEX Capture scenario=recover kind=WAKE authority_epoch=101 scope=40 effect=2 task=501 operation=2 asid=600 generation=1 address=0x401000 binding_epoch=2 wake_credit=Held max_wake=1"
    "LINUX_FUTEX PortalResult scenario=recover action=WakeCommit sender=504 opcode=0x4c600020 authority_epoch=101 scope=40 effect=2 task=501 operation=2 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=Applied mutation=true"
    "LINUX_FUTEX WakeCommit scenario=recover selected_wait=1 frozen_count=1 queue_removed=true wake_credit=Held"
    "LINUX_FUTEX PortalResult scenario=recover action=WakeCommit sender=504 opcode=0x4c600020 authority_epoch=101 scope=40 effect=2 task=501 operation=2 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=InvalidState mutation=false"
    "LINUX_FUTEX RevokeBegin scenario=recover reason=committed_wake_drain closed_epoch=101 authority_epoch=102 target=2 gate=closed"
    "LINUX_FUTEX PortalResult scenario=recover action=WakeCommit sender=504 opcode=0x4c600020 authority_epoch=101 scope=40 effect=2 task=501 operation=2 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=StaleAuthority mutation=false"
    "LINUX_FUTEX ClosurePublish scenario=recover phase=terminalize terminalizations=2 wakers_taken=2 credits_returned=false pending=true"
    "LINUX_FUTEX ClosurePublish scenario=recover phase=wake_outside_lock wait=true wake=true"
    "LINUX_FUTEX ClosurePublish scenario=recover phase=account publication=1 credits=wait+wake:Free pending=false"
    "LINUX_FUTEX RevokeComplete scenario=recover result=Applied queue=0 live=0 blocked=0 wakers=0 pending=false credits=wait+wake+timer:Free terminalizations=2"
    "LINUX_FUTEX_SCENARIO PASS scenario=recover terminalizations=2 wait_credit=Free wake_credit=Free timer_credit=Free queue=0 live=0 blocked=0 wakers=0 smp=1"
    "LINUX_FUTEX_SCHEDULER PASS scenario=recover policy=505 fallback_first_task=500 fallback_first_selection_attempt=1 observed_tick_delta="
    "LINUX_FUTEX_SCENARIO BEGIN scenario=expire authority_epoch=101 scope=41 asid=601 generation=1 address=0x401000 waiter=510 waker=511 shared_vm=true smp=1 scheduler_mode=existing_kernel_fifo_fallback"
    "LINUX_FUTEX Mismatch scenario=expire observed=0 expected=1 result=EAGAIN effect_created=false wait_credit_held=false mutation=false"
    "LINUX_FUTEX PortalResult scenario=expire action=WaitRegister sender=512 opcode=0x4c600002 authority_epoch=101 scope=41 effect=1 task=510 operation=1 address_space=601 generation=1 address=0x401000 binding_epoch=1 result=Applied mutation=true"
    "LINUX_FUTEX WaitRegister scenario=expire observed=0 expected=0 atomic=true queue=1 wait_credit=Held vm_restored=true"
    "LINUX_FUTEX Capture scenario=expire kind=WAKE authority_epoch=101 scope=41 effect=2 task=511 operation=2 asid=601 generation=1 address=0x401000 binding_epoch=1 wake_credit=Held max_wake=1"
    "LINUX_FUTEX Crash scenario=expire personality=512 previous_binding_epoch=1 binding_epoch=2 reason=real_user_page_fault fallback=kernel watchdog=armed cohort=2"
    "LINUX_FUTEX WatchdogExpire scenario=expire deadline="
    "linux_timeout=false"
    "LINUX_FUTEX RevokeBegin scenario=expire reason=recovery_watchdog_expired closed_epoch=101 authority_epoch=102 target=2 gate=closed"
    "LINUX_FUTEX PortalResult scenario=expire action=WakeCommit sender=512 opcode=0x4c600020 authority_epoch=101 scope=41 effect=2 task=511 operation=2 address_space=601 generation=1 address=0x401000 binding_epoch=1 result=StaleAuthority mutation=false"
    "LINUX_FUTEX ClosureAbort scenario=expire phase=terminalize terminalizations=2 delivery=Aborted linux_errno=none wakers_taken=2 credits_returned=false pending=true"
    "LINUX_FUTEX ClosureAbort scenario=expire phase=wake_outside_lock wait=true wake=true resumed=false"
    "LINUX_FUTEX ClosureAbort scenario=expire phase=account abort_wakes=2 credits=wait+wake+timer:Free pending=false etimedout=false"
    "LINUX_FUTEX RevokeComplete scenario=expire result=Applied queue=0 live=0 blocked=0 wakers=0 pending=false credits=wait+wake+timer:Free terminalizations=2"
    "LINUX_FUTEX_SCENARIO PASS scenario=expire terminalizations=2 wait_credit=Free wake_credit=Free timer_credit=Free queue=0 live=0 blocked=0 wakers=0 smp=1"
    "LINUX_FUTEX_SLICE PASS scenarios=recover+expire mismatch_eagain=true crash_rebind=true watchdog_expire=true committed_drain=true uncommitted_abort=true linux_timeout=false unified_registry=false smp=1"
    "LINUX_FUTEX_CORE BEGIN workload=linux-round4-futex-smoke adapted=true elf=ET_EXEC entry=0x401000 segments=4"
    "LINUX_FUTEX_CORE PASS workload=linux-round4-futex-smoke stdout_exact=true mmap_pages=8 clones=3 waits=4 wakes=2 requeues=1 affected_count=2"
    "READINESS_LIFECYCLE PASS frozen_delivery=1 recovery_adoptions=6 old_binding_rejected=true unadopted_subscription_rejected=true domain_snapshot_invalidated=true post_ready_domain_invalidation=true ready_wins_timeout=true timeout_wins_ready=true revoke_wins_ready=true positive_timeout_timer=true publication_acks=3 duplicate_publication_rejected=true stale_service_generation_rejected=true single_terminalization=true quiescent=true"
    "LINUX_EPOLL_SLICE BEGIN workload=linux-round5-epoll format=ELF64 type=ET_EXEC adapted_regular_file_eperm=true registry=common readiness=kernel_owned smp=1"
    "EFFECT_REGISTRY Quiescent workload=linux-round5-epoll live=0 pending_publications=0 subscriptions=0 queued=0 unpublished_deliveries=0 credits=Free"
    "LINUX_EPOLL_SLICE PASS workload=linux-round5-epoll adapted=true syscalls=23 pipe_et=true pipe_oneshot=true socket_lt=true regular_file_eperm=true sample_arm=atomic registry_quiescent=true"
    "FILESYSTEM_LIFECYCLE PASS pager_crash_adopt=true precommit_adopt=true postcommit_fence=true pwrite_commit_first=true pwrite_revoke_first=true reset_timeout_tombstone=true iotlb_timeout_tombstone=true"
    "LINUX_FS_SLICE BEGIN workload=linux-runtime-fs-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=14"
    "EFFECT_REGISTRY Quiescent workload=linux-runtime-fs production_root=95 production_effects=16 live=0 pending_publications=0 credits=Free"
    "LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=14"
    "COMPOSITION_SLICE BEGIN root_scope=70 authority_epoch=121 domains=5 bounded=true single_cpu=true runtime_fs=false runtime_net=false virtio_adapter=external_stage5b_consistency"
    "COMPOSITION_SLICE PASS root_scope=70 authority_epoch_old=121 authority_epoch_new=122 domains=5 causal_nodes=6 causal_edges=5 parent_chain_immutable=true stale_parent_rejected=true stale_target_rejected=true delegated_credits=5 binding_epochs=scheduler:4,pager:2,personality:2,readiness:2,virtio:3 device_generations=virtio:3->4 frozen_domains=5 cohort_source=registry_live_selection closure_order=scheduler,pager,virtio,readiness,personality child_first=true live_descendant_rejected=true closure_receipts=5 receipt_sequences=6 receipt_revision=6 receipt_acceptance=authoritative closure_sequences_unique=true timeout_receipts=1 timeout_replay_rejected=true duplicate_receipt_rejected=true out_of_order_receipt_rejected=true virtio_tombstones=1 virtio_retries=1 stale_child_rejected=true stale_commit_rejected=true stale_receipt_rejected=true virtio_evidence=component_consistency identity_preserving=false credits_free=5 live=0 pending=0 final_quiescent=true bounded=true single_cpu=true runtime_fs=false runtime_net=false"
    "CSER REJECT_STALE action=Prepare authority_epoch=41 proposal_binding_epoch=1 current_binding_epoch=4 proposal_task=100"
    "IOMMU_PROBE PASS result=FAIL_CLOSED reason=IOTLB_INVALIDATION_UNAVAILABLE ostd=0.18.0 authority_epoch=41"
    "SPIKE_RESULT PASS"
)

previous=0
for pattern in "${patterns[@]}"; do
    line=$(grep -nF -m1 "$pattern" "$log" | cut -d: -f1 || true)
    if [[ -z "$line" ]]; then
        echo "missing serial assertion: $pattern" >&2
        exit 1
    fi
    if (( line < previous )); then
        echo "out-of-order serial assertion: $pattern" >&2
        exit 1
    fi
    previous=$line
done

awk '
    function fail(message) {
        print "fallback trace assertion failed: " message > "/dev/stderr"
        failed = 1
        exit 1
    }
    function field(name,    i, prefix) {
        prefix = name "="
        for (i = 1; i <= NF; i++) {
            if (index($i, prefix) == 1)
                return substr($i, length(prefix) + 1)
        }
        return ""
    }
    {
        sub(/\r$/, "")
    }
    /^CSER Crash authority_epoch=41 previous_binding_epoch=1 binding_epoch=2 / {
        base_crashes++
        if (field("tick") !~ /^[0-9]+$/)
            fail("base crash has a non-numeric tick: " $0)
        base_crash_tick = field("tick") + 0
        base_crash_line = NR
    }
    /^CSER Crash authority_epoch=41 previous_binding_epoch=2 binding_epoch=3 / {
        linux_crashes++
        if (field("tick") !~ /^[0-9]+$/)
            fail("Linux crash has a non-numeric tick: " $0)
        linux_crash_tick = field("tick") + 0
        linux_crash_line = NR
    }
    /^CSER Crash authority_epoch=41 previous_binding_epoch=3 binding_epoch=4 / {
        futex_crashes++
        if (field("tick") !~ /^[0-9]+$/)
            fail("Linux futex crash has a non-numeric tick: " $0)
        futex_crash_tick = field("tick") + 0
        futex_crash_line = NR
    }
    /^CSER FallbackPick authority_epoch=41 binding_epoch=2 / {
        base_attempts_seen++
        if (field("tick") !~ /^[0-9]+$/ || field("selection_attempt") != base_attempts_seen)
            fail("base fallback attempts are not dense numeric ordinals: " $0)
        if (field("selection_attempt") == "1")
            base_first_attempts++
        if (!base_pick_seen) {
            base_pick_seen = 1
            if (field("task") != "200" || field("selection_attempt") != "1")
                fail("base first pick was not task 200 on selection attempt 1: " $0)
            base_pick_tick = field("tick") + 0
            base_pick_line = NR
        }
    }
    /^CSER FallbackPick authority_epoch=41 binding_epoch=3 / {
        linux_attempts_seen++
        if (field("tick") !~ /^[0-9]+$/ || field("selection_attempt") != linux_attempts_seen)
            fail("Linux fallback attempts are not dense numeric ordinals: " $0)
        if (field("selection_attempt") == "1")
            linux_first_attempts++
        if (!linux_pick_seen) {
            linux_pick_seen = 1
            if (field("task") != "400" || field("selection_attempt") != "1")
                fail("Linux first pick was not task 400 on selection attempt 1: " $0)
            linux_pick_tick = field("tick") + 0
            linux_pick_line = NR
        }
    }
    /^CSER FallbackPick authority_epoch=41 binding_epoch=4 / {
        attempt = field("selection_attempt")
        if (field("tick") !~ /^[0-9]+$/ || attempt !~ /^[0-9]+$/)
            fail("Linux futex fallback pick has a non-numeric tick/attempt: " $0)
        if (!futex_slice_complete) {
            futex_dense_attempts++
            if (attempt != futex_dense_attempts)
                fail("Stage 6B.1 Linux futex fallback attempts are not dense ordinals: " $0)
        } else {
            if (attempt + 0 <= futex_last_attempt)
                fail("post-6B.1 fallback attempts are not strictly increasing: " $0)
            post_futex_attempts++
        }
        futex_last_attempt = attempt + 0
        if (attempt == "1")
            futex_first_attempts++
        if (!futex_pick_seen) {
            futex_pick_seen = 1
            if (field("task") != "500" || attempt != "1")
                fail("Linux futex first pick was not task 500 on selection attempt 1: " $0)
            futex_pick_tick = field("tick") + 0
            futex_pick_line = NR
        }
    }
    /^LINUX_FUTEX_SLICE PASS scenarios=recover\+expire / {
        futex_slice_passes++
        if (futex_slice_passes != 1)
            fail("duplicate Stage 6B.1 futex slice PASS")
        futex_slice_complete = 1
    }
    /^OSTD_PROBE PASS api=UserMode\+VmSpace syscall=true page_fault=true authority_epoch=41$/ {
        base_api_passes++
        base_api_line = NR
    }
    /^OSTD_PROBE PASS fallback_first_task=/ {
        base_passes++
        if ($0 !~ /^OSTD_PROBE PASS fallback_first_task=200 fallback_first_selection_attempt=1 observed_tick_delta=[0-9]+ tick_delta_diagnostic=true authority_epoch=41 binding_epoch=2$/)
            fail("malformed base fallback PASS: " $0)
        base_reported_delta = field("observed_tick_delta") + 0
        base_pass_line = NR
    }
    /^LINUX_SCHEDULER PASS workload=linux-hello / {
        linux_passes++
        if ($0 !~ /^LINUX_SCHEDULER PASS workload=linux-hello policy=404 fallback_first_task=400 fallback_first_selection_attempt=1 observed_tick_delta=[0-9]+ tick_delta_diagnostic=true scoped_proposal_cleared=true$/)
            fail("malformed Linux fallback PASS: " $0)
        linux_reported_delta = field("observed_tick_delta") + 0
    }
    /^LINUX_FUTEX_SCHEDULER PASS scenario=recover / {
        futex_passes++
        if ($0 !~ /^LINUX_FUTEX_SCHEDULER PASS scenario=recover policy=505 fallback_first_task=500 fallback_first_selection_attempt=1 observed_tick_delta=[0-9]+ tick_delta_diagnostic=true$/)
            fail("malformed Linux futex fallback PASS: " $0)
        futex_reported_delta = field("observed_tick_delta") + 0
    }
    END {
        if (failed)
            exit 1
        if (base_crashes != 1 || linux_crashes != 1 || futex_crashes != 1)
            fail("expected one base, one Linux, and one Linux futex scheduler crash")
        if (base_api_passes != 1)
            fail("expected exactly one base user-probe PASS")
        if (!base_pick_seen || !linux_pick_seen || !futex_pick_seen)
            fail("missing first fallback pick")
        if (base_first_attempts != 1 || linux_first_attempts != 1 || futex_first_attempts != 1)
            fail("selection attempt 1 must appear exactly once in each binding epoch")
        if (base_passes != 1 || linux_passes != 1 || futex_passes != 1)
            fail("expected exactly one base, one Linux, and one Linux futex fallback PASS")
        if (base_pick_line <= base_crash_line || linux_pick_line <= linux_crash_line || futex_pick_line <= futex_crash_line)
            fail("a first fallback pick was serialized before its Crash")
        if (base_api_line <= base_crash_line || base_api_line >= base_pass_line)
            fail("base user-probe PASS was not serialized between Crash and fallback evidence")
        if (futex_slice_passes != 1 || post_futex_attempts == 0)
            fail("missing Stage 6B.1 boundary or post-6B.1 increasing fallback evidence")
        if (base_pick_tick < base_crash_tick || base_reported_delta != base_pick_tick - base_crash_tick)
            fail("base fallback tick diagnostic does not match Crash -> first pick")
        if (linux_pick_tick < linux_crash_tick || linux_reported_delta != linux_pick_tick - linux_crash_tick)
            fail("Linux fallback tick diagnostic does not match Crash -> first pick")
        if (futex_pick_tick < futex_crash_tick || futex_reported_delta != futex_pick_tick - futex_crash_tick)
            fail("Linux futex fallback tick diagnostic does not match Crash -> first pick")
    }
' "$log"

awk '
    function fail(message) {
        print "scheduler lease trace assertion failed: " message > "/dev/stderr"
        failed = 1
        exit 1
    }
    function field(name,    i, prefix) {
        prefix = name "="
        for (i = 1; i <= NF; i++) {
            if (index($i, prefix) == 1)
                return substr($i, length(prefix) + 1)
        }
        return ""
    }
    function expected_key(binding, task, source) {
        return binding ":" task ":" source
    }
    BEGIN {
        expected[expected_key(1, 100, "unscoped")] = 1
        expected[expected_key(1, 200, "unscoped")] = 1
        expected[expected_key(2, 404, "unscoped")] = 1
        expected[expected_key(2, 400, "scoped")] = 1
        expected[expected_key(3, 505, "unscoped")] = 1
        expected[expected_key(3, 500, "scoped")] = 1
    }
    {
        sub(/\r$/, "")
    }
    /^CSER Prepare authority_epoch=41 / {
        prepare_line[expected_key(field("binding_epoch"), field("proposal_task"), "unscoped")] = NR
    }
    /^CSER PrepareScoped service=scheduler scheduler_authority_epoch=41 / {
        prepare_line[expected_key(field("binding_epoch"), field("proposal_task"), "scoped")] = NR
    }
    /^CSER LeaseRenew action=Prepare / {
        renewals++
        if ($0 !~ /^CSER LeaseRenew action=Prepare authority_epoch=41 binding_epoch=[0-9]+ proposal_task=[0-9]+ source=(unscoped|scoped) tick=[0-9]+ previous_deadline_tick=[0-9]+ lease_deadline_tick=[0-9]+ lease_ticks=64$/)
            fail("malformed renewal receipt: " $0)
        key = expected_key(field("binding_epoch"), field("proposal_task"), field("source"))
        if (!(key in expected))
            fail("unexpected renewal identity: " key)
        seen[key]++
        if (seen[key] != 1)
            fail("duplicate renewal identity: " key)
        if (!(key in prepare_line) || prepare_line[key] >= NR)
            fail("renewal did not follow its accepted Prepare receipt: " key)
        tick = field("tick") + 0
        deadline = field("lease_deadline_tick") + 0
        if (deadline != tick + 64)
            fail("renewal did not restore the complete 64-tick lease: " $0)
    }
    /reason=policy_lease_expired/ {
        fail("accepted policy proposal still expired before its intentional crash: " $0)
    }
    END {
        if (failed)
            exit 1
        if (renewals != 6)
            fail("expected six accepted-proposal renewals, observed " renewals)
        for (key in expected) {
            if (seen[key] != 1)
                fail("missing renewal identity: " key)
        }
    }
' "$log"

if [[ $(grep -cF 'PAGER Complete scenario=recover fault=1 terminal=Completed' "$log") -ne 1 ]]; then
    echo "recover fault did not complete exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER REJECT_NO_SUPERVISOR scenario=recover stage=pre_rebind action=Commit' "$log") -ne 1 ]]; then
    echo "recover path did not reject exactly one pre-rebind reply" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER REJECT_STALE scenario=recover stage=post_rebind action=Commit' "$log") -ne 1 ]]; then
    echo "recover path did not reject exactly one post-rebind stale reply" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER Abort scenario=timeout fault=2 terminal=Aborted' "$log") -ne 1 ]]; then
    echo "timeout fault did not abort exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER RevokeBegin scenario=timeout scope=21' "$log") -ne 1 ]]; then
    echo "timeout scope did not publish RevokeBegin exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER RevokeComplete scenario=timeout scope=21' "$log") -ne 1 ]]; then
    echo "timeout scope did not publish RevokeComplete exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER ClientResume scenario=recover fault=1' "$log") -ne 1 ]]; then
    echo "recover client did not resume exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER CleanupDrop scenario=timeout fault=2 prepared_dropped=true outside_lock=true' "$log") -ne 1 ]]; then
    echo "timeout fault did not clean its retained frame exactly once outside the state lock" >&2
    exit 1
fi

require_exact_count() {
    local expected=$1
    local pattern=$2
    local description=$3
    local actual
    actual=$(grep -cF "$pattern" "$log" || true)
    if [[ "$actual" -ne "$expected" ]]; then
        echo "$description: expected $expected, observed $actual ($pattern)" >&2
        exit 1
    fi
}

require_exact_line_count() {
    local expected=$1
    local line=$2
    local description=$3
    local actual
    actual=$(awk -v wanted="$line" '
        { sub(/\r$/, "") }
        $0 == wanted { count++ }
        END { print count + 0 }
    ' "$log")
    if [[ "$actual" -ne "$expected" ]]; then
        echo "$description: expected $expected, observed $actual ($line)" >&2
        exit 1
    fi
}

require_regex_count() {
    local expected=$1
    local pattern=$2
    local description=$3
    local actual
    actual=$(awk -v pattern="$pattern" '
        { sub(/\r$/, "") }
        $0 ~ pattern { count++ }
        END { print count + 0 }
    ' "$log")
    if [[ "$actual" -ne "$expected" ]]; then
        echo "$description: expected $expected, observed $actual ($pattern)" >&2
        exit 1
    fi
}

line_of_exact() {
    local line=$1
    awk -v wanted="$line" '
        { sub(/\r$/, "") }
        $0 == wanted { print NR }
    ' "$log"
}

# The Projection oracle is deliberately scenario-aware.  It pairs every
# compressed semantic state with its PortalResult, validates the complete token
# identity and allowed order, and rejects any missing or additional receipt.
awk -f "$script_dir/assert-linux-projections.awk" "$log"
awk -f "$script_dir/assert-linux-futex.awk" "$log"
awk -f "$script_dir/assert-linux-futex-core.awk" "$log"
awk -f "$script_dir/assert-linux-epoll.awk" "$log"
awk -f "$script_dir/assert-composition.awk" "$log"

# Keep the retained Round 4 parser honest. A duplicate terminal receipt, a
# false requeue affected count, and a stale-v1 mutation claim must all fail.
if {
    cat "$log"
    grep -F -m1 'LINUX_FUTEX_CORE PASS workload=linux-round4-futex-smoke' "$log"
} | awk -f "$script_dir/assert-linux-futex-core.awk" >/dev/null 2>&1; then
    echo 'linux futex core oracle accepted duplicate terminal evidence' >&2
    exit 1
fi
if sed '0,/op=REQUEUE woken=1 moved=1 affected=2/{s/affected=2/affected=1/}' "$log" |
    awk -f "$script_dir/assert-linux-futex-core.awk" >/dev/null 2>&1; then
    echo 'linux futex core oracle accepted a false requeue affected count' >&2
    exit 1
fi
if sed '0,/LateOldGeneration .* mutation=false/{s/mutation=false/mutation=true/}' "$log" |
    awk -f "$script_dir/assert-linux-futex-core.awk" >/dev/null 2>&1; then
    echo 'linux futex core oracle accepted a mutating stale-v1 call' >&2
    exit 1
fi

require_exact_line_count 1 \
    'READINESS_LIFECYCLE PASS frozen_delivery=1 recovery_adoptions=6 old_binding_rejected=true unadopted_subscription_rejected=true domain_snapshot_invalidated=true post_ready_domain_invalidation=true ready_wins_timeout=true timeout_wins_ready=true revoke_wins_ready=true positive_timeout_timer=true publication_acks=3 duplicate_publication_rejected=true stale_service_generation_rejected=true single_terminalization=true quiescent=true' \
    'readiness lifecycle race/closure receipt count mismatch'

# Keep the epoll parser honest with two cheap mutations of the observed QEMU
# trace: duplicate terminal evidence and a false edge-triggered result must
# both be rejected by the strict oracle.
if {
    cat "$log"
    grep -F -m1 'LINUX_EPOLL_SLICE PASS workload=linux-round5-epoll' "$log"
} | awk -f "$script_dir/assert-linux-epoll.awk" >/dev/null 2>&1; then
    echo 'linux epoll oracle accepted duplicate terminal evidence' >&2
    exit 1
fi
if sed '0,/delivery=2 sequence=2 count=0/{s/delivery=2 sequence=2 count=0/delivery=2 sequence=2 count=1/}' "$log" |
    awk -f "$script_dir/assert-linux-epoll.awk" >/dev/null 2>&1; then
    echo 'linux epoll oracle accepted a false second edge delivery' >&2
    exit 1
fi

# The composition oracle must reject both an extra domain-closure receipt and
# a stale-receipt claim that reports mutation.
if {
    cat "$log"
    grep -F -m1 'COMPOSITION_CLOSURE Issue root_scope=70 domain_scope=71 domain=scheduler' "$log"
} | awk -f "$script_dir/assert-composition.awk" >/dev/null 2>&1; then
    echo 'composition oracle accepted a duplicate closure receipt' >&2
    exit 1
fi
if sed '0,/COMPOSITION_REJECT stage=closing kind=stale_receipt .* mutation=false/{s/mutation=false/mutation=true/}' "$log" |
    awk -f "$script_dir/assert-composition.awk" >/dev/null 2>&1; then
    echo 'composition oracle accepted a mutating stale receipt' >&2
    exit 1
fi

require_exact_count 1 \
    'CSER PrepareScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=2 workload_authority_epoch=91 scope=30 effect=0 proposal_task=400' \
    'linux scheduler scoped proposal count mismatch'
require_exact_count 1 \
    'CSER CrashScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=3 workload_authority_epoch=91 scope=30 effect=0 pending_scoped_cleared=true fallback=kernel_fifo' \
    'linux scheduler scoped crash count mismatch'
require_exact_count 1 \
    'LINUX_SCHEDULER PASS workload=linux-hello' \
    'linux scheduler fallback receipt count mismatch'

for event in Register PrepareImage Crash Commit Complete GuestResume PASS; do
    require_exact_count 1 \
        "LINUX_CODE_PAGER $event workload=linux-hello" \
        "linux code-pager $event count mismatch"
done
require_exact_count 1 \
    'LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_crash' \
    'linux code-pager post-crash stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_rebind' \
    'linux code-pager post-rebind stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_CODE_PAGER REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind' \
    'linux code-pager no-supervisor rejection count mismatch'

require_exact_count 1 \
    'LINUX_GUEST stdout=hello from linux-hello' \
    'linux guest output publication count mismatch'
require_exact_count 1 \
    'LINUX_GUEST stdout=' \
    'unexpected additional linux guest output publication'
require_exact_count 1 \
    'LINUX_SYSCALL BackendCommit workload=linux-hello personality=401 effect=1 kind=write binding_epoch=1 result=Committed' \
    'linuxd-v1 backend commit count mismatch'
require_exact_count 1 \
    'LINUX_PORTAL Queue workload=linux-hello sender=401 action=Reply effect=1 authority_epoch=91 scope=30 task=400 operation=1 binding_epoch=1 delivery=after_crash' \
    'linuxd-v1 delayed full-token packet count mismatch'
require_exact_count 1 \
    'LINUX_PORTAL Queue workload=linux-hello' \
    'unexpected additional Linux portal queued packet'
require_exact_count 1 \
    'LINUX_SYSCALL BackendCommit workload=linux-hello personality=403 effect=1 kind=write binding_epoch=2 result=AlreadyCommitted' \
    'linuxd-v2 duplicate backend fencing count mismatch'
require_exact_count 2 \
    'LINUX_SYSCALL BackendCommit workload=linux-hello' \
    'unexpected additional linux write backend commit attempt'
require_exact_count 1 \
    'LINUX_SYSCALL Reply workload=linux-hello replacement=403 effect=1 kind=write' \
    'linux write reply count mismatch'
require_exact_count 1 \
    'LINUX_PERSONALITY Crash workload=linux-hello supervisor=401' \
    'linux personality crash count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_crash action=Reply effect=1' \
    'linux personality post-crash stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_rebind action=Reply effect=1' \
    'linux personality post-rebind stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind action=Reply effect=1' \
    'linux personality no-supervisor rejection count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL Commit workload=linux-hello replacement=403 effect=2 kind=exit_group' \
    'linux exit-group terminalization count mismatch'
require_exact_count 1 \
    'LINUX_GUEST Exit workload=linux-hello status=0 resumed_after_exit=false terminal=Exited' \
    'linux guest exit count mismatch'
require_exact_count 1 \
    'LINUX_SLICE PASS workload=linux-hello' \
    'linux slice receipt count mismatch'
require_exact_count 1 'SPIKE_RESULT PASS' 'overall prototype receipt count mismatch'

require_exact_count 1 \
    'LINUX_REVOKE ClosureStep scope=31 effect=5 from=ReplyPrepared to=Aborted backend_commits=0 replies=0 resumes=0 aborts=1 steps=1 waker_taken=true wake_published=true waker_dropped=true' \
    'revoke-before-commit closure receipt count mismatch'
require_exact_count 1 \
    'LINUX_REVOKE RevokeComplete parent_scope=30 scope=31 authority_epoch=92 target_count=1 steps=1 live_effects=0 waker_present=false wake_publications=1 state=Revoked' \
    'revoke-before-commit quiescent completion count mismatch'
require_exact_count 1 \
    'LINUX_REVOKE ClosureStep scope=32 effect=6 from=BackendCommitted to=Completed backend_commits=1 replies=1 resumes=1 aborts=0 steps=1 waker_taken=true wake_published=true waker_dropped=true' \
    'commit-before-revoke closure receipt count mismatch'
require_exact_count 1 \
    'LINUX_REVOKE RevokeComplete parent_scope=30 scope=32 authority_epoch=92 target_count=1 steps=1 live_effects=0 waker_present=false wake_publications=1 state=Revoked' \
    'commit-before-revoke quiescent completion count mismatch'
require_exact_count 2 \
    'LINUX_REVOKE ClosureStep scope=' \
    'unexpected additional or missing revoke closure step'
require_exact_count 2 \
    'LINUX_REVOKE RevokeComplete parent_scope=30 scope=' \
    'unexpected additional or missing quiescent revoke completion'

require_exact_count 1 \
    'CSER PrepareScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=3 workload_authority_epoch=101 scope=40 effect=1 proposal_task=500' \
    'linux futex scheduler scoped proposal count mismatch'
require_exact_count 1 \
    'CSER CrashScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=4 workload_authority_epoch=101 scope=40 effect=1 pending_scoped_cleared=true fallback=kernel_fifo' \
    'linux futex scheduler scoped crash count mismatch'
require_exact_count 1 \
    'LINUX_FUTEX_SCHEDULER PASS scenario=recover' \
    'linux futex scheduler fallback receipt count mismatch'

require_exact_count 22 \
    'LINUX_FUTEX PortalResult ' \
    'linux futex PortalResult count mismatch'
require_exact_count 22 \
    'LINUX_FUTEX Projection ' \
    'linux futex Projection count mismatch'

require_exact_count 2 \
    'LINUX_FUTEX Mismatch scenario=' \
    'linux futex mismatch count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX Mismatch scenario=recover observed=0 expected=1 result=EAGAIN effect_created=false wait_credit_held=false mutation=false' \
    'recover mismatch receipt count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX Mismatch scenario=expire observed=0 expected=1 result=EAGAIN effect_created=false wait_credit_held=false mutation=false' \
    'expire mismatch receipt count mismatch'

require_exact_count 2 \
    'LINUX_FUTEX WaitRegister scenario=' \
    'linux futex successful wait registration count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX WaitRegister scenario=recover observed=0 expected=0 atomic=true queue=1 wait_credit=Held vm_restored=true' \
    'recover wait registration receipt count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX WaitRegister scenario=expire observed=0 expected=0 atomic=true queue=1 wait_credit=Held vm_restored=true' \
    'expire wait registration receipt count mismatch'

require_regex_count 2 \
    '^LINUX_FUTEX Capture scenario=(recover|expire) kind=WAKE ' \
    'linux futex WAKE capture count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX Capture scenario=recover kind=WAKE authority_epoch=101 scope=40 effect=2 task=501 operation=2 asid=600 generation=1 address=0x401000 binding_epoch=2 wake_credit=Held max_wake=1' \
    'recover WAKE capture count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX Capture scenario=expire kind=WAKE authority_epoch=101 scope=41 effect=2 task=511 operation=2 asid=601 generation=1 address=0x401000 binding_epoch=1 wake_credit=Held max_wake=1' \
    'expire WAKE capture count mismatch'

require_exact_count 2 \
    'LINUX_FUTEX Crash scenario=' \
    'linux futex personality crash count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX Crash scenario=recover personality=502 previous_binding_epoch=1 binding_epoch=2 reason=real_user_page_fault fallback=kernel watchdog=armed cohort=1' \
    'recover personality crash count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX Crash scenario=expire personality=512 previous_binding_epoch=1 binding_epoch=2 reason=real_user_page_fault fallback=kernel watchdog=armed cohort=2' \
    'expire personality crash count mismatch'

require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=Snapshot sender=504 opcode=0x4c600010 authority_epoch=101 scope=40 effect=0 task=504 operation=0 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=Applied mutation=true' \
    'recover Snapshot success count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=Ready sender=504 opcode=0x4c600011 authority_epoch=101 scope=40 effect=0 task=504 operation=0 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=Applied mutation=true' \
    'recover Ready success count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=Rebind sender=504 opcode=0x4c600012 authority_epoch=101 scope=40 effect=0 task=504 operation=0 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=Applied mutation=true' \
    'recover Rebind success count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=RecoverNext sender=504 opcode=0x4c600013 authority_epoch=101 scope=40 effect=0 task=504 operation=0 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=Applied mutation=false' \
    'recover RecoverNext success count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=Adopt sender=504 opcode=0x4c600014 authority_epoch=101 scope=40 effect=1 task=500 operation=1 address_space=600 generation=1 address=0x401000 binding_epoch=1 result=Applied mutation=true' \
    'recover Adopt success count mismatch'

require_exact_line_count 1 \
    'LINUX_FUTEX WatchdogCancel scenario=recover effect=1 binding_epoch=2 timer_credit=Free queued_wait_retained=true' \
    'recover watchdog cancellation count mismatch'
require_regex_count 1 \
    '^LINUX_FUTEX WatchdogExpire scenario=expire deadline=[0-9]+ authority_epoch=101 scope=41 cohort=2 linux_timeout=false$' \
    'expire watchdog receipt count mismatch'

require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=WakeCommit sender=504 opcode=0x4c600020 authority_epoch=101 scope=40 effect=2 task=501 operation=2 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=Applied mutation=true' \
    'recover successful WakeCommit count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX WakeCommit scenario=recover selected_wait=1 frozen_count=1 queue_removed=true wake_credit=Held' \
    'recover committed wake summary count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=WakeCommit sender=504 opcode=0x4c600020 authority_epoch=101 scope=40 effect=2 task=501 operation=2 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=InvalidState mutation=false' \
    'recover duplicate WakeCommit rejection count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=recover action=WakeCommit sender=504 opcode=0x4c600020 authority_epoch=101 scope=40 effect=2 task=501 operation=2 address_space=600 generation=1 address=0x401000 binding_epoch=2 result=StaleAuthority mutation=false' \
    'recover post-revoke WakeCommit rejection count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX PortalResult scenario=expire action=WakeCommit sender=512 opcode=0x4c600020 authority_epoch=101 scope=41 effect=2 task=511 operation=2 address_space=601 generation=1 address=0x401000 binding_epoch=1 result=StaleAuthority mutation=false' \
    'expire post-revoke WakeCommit rejection count mismatch'

require_exact_count 2 \
    'LINUX_FUTEX RevokeBegin scenario=' \
    'linux futex RevokeBegin count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX RevokeBegin scenario=recover reason=committed_wake_drain closed_epoch=101 authority_epoch=102 target=2 gate=closed' \
    'recover RevokeBegin count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX RevokeBegin scenario=expire reason=recovery_watchdog_expired closed_epoch=101 authority_epoch=102 target=2 gate=closed' \
    'expire RevokeBegin count mismatch'

require_exact_count 3 \
    'LINUX_FUTEX ClosurePublish scenario=recover phase=' \
    'recover closure phase count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX ClosurePublish scenario=recover phase=terminalize terminalizations=2 wakers_taken=2 credits_returned=false pending=true' \
    'recover terminalize closure phase count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX ClosurePublish scenario=recover phase=wake_outside_lock wait=true wake=true' \
    'recover outside-lock wake phase count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX ClosurePublish scenario=recover phase=account publication=1 credits=wait+wake:Free pending=false' \
    'recover publication accounting phase count mismatch'
require_exact_count 1 \
    'LINUX_FUTEX ClosurePublish scenario=recover phase=account publication=' \
    'unexpected additional recover wake publication'

require_exact_count 3 \
    'LINUX_FUTEX ClosureAbort scenario=expire phase=' \
    'expire closure phase count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX ClosureAbort scenario=expire phase=terminalize terminalizations=2 delivery=Aborted linux_errno=none wakers_taken=2 credits_returned=false pending=true' \
    'expire terminalize closure phase count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX ClosureAbort scenario=expire phase=wake_outside_lock wait=true wake=true resumed=false' \
    'expire outside-lock wake phase count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX ClosureAbort scenario=expire phase=account abort_wakes=2 credits=wait+wake+timer:Free pending=false etimedout=false' \
    'expire abort accounting phase count mismatch'

require_exact_count 2 \
    'LINUX_FUTEX RevokeComplete scenario=' \
    'linux futex RevokeComplete count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX RevokeComplete scenario=recover result=Applied queue=0 live=0 blocked=0 wakers=0 pending=false credits=wait+wake+timer:Free terminalizations=2' \
    'recover final quiescent closure mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX RevokeComplete scenario=expire result=Applied queue=0 live=0 blocked=0 wakers=0 pending=false credits=wait+wake+timer:Free terminalizations=2' \
    'expire final quiescent closure mismatch'

require_exact_count 2 \
    'LINUX_FUTEX GuestResume scenario=recover ' \
    'recover guest resume count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX GuestResume scenario=recover role=waiter task=500 linux_result=0 done=true resumes=1' \
    'recover waiter resume count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX GuestResume scenario=recover role=waker task=501 linux_result=1 done=true resumes=1' \
    'recover waker resume count mismatch'
require_exact_count 2 \
    'LINUX_FUTEX GuestAbortExit scenario=expire ' \
    'expire guest abort-exit count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX GuestAbortExit scenario=expire role=waiter task=510 delivery=Aborted resumed=false linux_errno_written=false ecanceled=false etimedout=false' \
    'expire waiter abort-exit count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX GuestAbortExit scenario=expire role=waker task=511 delivery=Aborted resumed=false linux_errno_written=false ecanceled=false etimedout=false' \
    'expire waker abort-exit count mismatch'

# The two guest Tasks are independent after kernel-owned publication.  Their
# relative order is scheduler-dependent, but both must consume exactly one
# continuation after quiescent closure and before the scenario PASS.
recover_close_line=$(line_of_exact \
    'LINUX_FUTEX RevokeComplete scenario=recover result=Applied queue=0 live=0 blocked=0 wakers=0 pending=false credits=wait+wake+timer:Free terminalizations=2')
recover_waiter_line=$(line_of_exact \
    'LINUX_FUTEX GuestResume scenario=recover role=waiter task=500 linux_result=0 done=true resumes=1')
recover_waker_line=$(line_of_exact \
    'LINUX_FUTEX GuestResume scenario=recover role=waker task=501 linux_result=1 done=true resumes=1')
recover_pass_line=$(line_of_exact \
    'LINUX_FUTEX_SCENARIO PASS scenario=recover terminalizations=2 wait_credit=Free wake_credit=Free timer_credit=Free queue=0 live=0 blocked=0 wakers=0 smp=1')
if (( recover_waiter_line <= recover_close_line || recover_waiter_line >= recover_pass_line ||
      recover_waker_line <= recover_close_line || recover_waker_line >= recover_pass_line )); then
    echo 'recover guest completion escaped the RevokeComplete -> scenario PASS interval' >&2
    exit 1
fi

expire_close_line=$(line_of_exact \
    'LINUX_FUTEX RevokeComplete scenario=expire result=Applied queue=0 live=0 blocked=0 wakers=0 pending=false credits=wait+wake+timer:Free terminalizations=2')
expire_waiter_line=$(line_of_exact \
    'LINUX_FUTEX GuestAbortExit scenario=expire role=waiter task=510 delivery=Aborted resumed=false linux_errno_written=false ecanceled=false etimedout=false')
expire_waker_line=$(line_of_exact \
    'LINUX_FUTEX GuestAbortExit scenario=expire role=waker task=511 delivery=Aborted resumed=false linux_errno_written=false ecanceled=false etimedout=false')
expire_pass_line=$(line_of_exact \
    'LINUX_FUTEX_SCENARIO PASS scenario=expire terminalizations=2 wait_credit=Free wake_credit=Free timer_credit=Free queue=0 live=0 blocked=0 wakers=0 smp=1')
if (( expire_waiter_line <= expire_close_line || expire_waiter_line >= expire_pass_line ||
      expire_waker_line <= expire_close_line || expire_waker_line >= expire_pass_line )); then
    echo 'expire guest completion escaped the RevokeComplete -> scenario PASS interval' >&2
    exit 1
fi

require_exact_count 2 \
    'LINUX_FUTEX_SCENARIO PASS scenario=' \
    'linux futex scenario PASS count mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX_SCENARIO PASS scenario=recover terminalizations=2 wait_credit=Free wake_credit=Free timer_credit=Free queue=0 live=0 blocked=0 wakers=0 smp=1' \
    'recover final scenario closure mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX_SCENARIO PASS scenario=expire terminalizations=2 wait_credit=Free wake_credit=Free timer_credit=Free queue=0 live=0 blocked=0 wakers=0 smp=1' \
    'expire final scenario closure mismatch'
require_exact_line_count 1 \
    'LINUX_FUTEX_SLICE PASS scenarios=recover+expire mismatch_eagain=true crash_rebind=true watchdog_expire=true committed_drain=true uncommitted_abort=true linux_timeout=false unified_registry=false smp=1' \
    'linux futex slice PASS count mismatch'

guest_exit_line=$(grep -nF -m1 \
    'LINUX_GUEST Exit workload=linux-hello status=0 resumed_after_exit=false terminal=Exited' \
    "$log" | cut -d: -f1 || true)
if [[ -z "$guest_exit_line" ]]; then
    echo "missing Linux guest exit terminalization" >&2
    exit 1
fi
if tail -n "+$((guest_exit_line + 1))" "$log" | grep -Eq \
    'LINUX_(SYSCALL (Capture|Prepare|BackendCommit|Reply|Commit) workload=linux-hello|PORTAL Deliver workload=linux-hello|GUEST (Block|Resume|stdout=)|PERSONALITY (Dispatch|Crash|Fallback|FreshSpawn|RecoverySnapshot|Ready|Rebind))'; then
    echo "successful Linux guest/syscall activity observed after guest exit" >&2
    exit 1
fi

for forbidden in \
    'PAGER Commit scenario=timeout' \
    'PAGER Complete scenario=timeout' \
    'PAGER ClientResume scenario=timeout' \
    'PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=true' \
    'PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=false wake_pending=true' \
    'CSER Commit authority_epoch=41 binding_epoch=2 proposal_task=400' \
    'LINUX_SYSCALL Reply workload=linux-hello replacement=401' \
    'LINUX_SYSCALL Reply workload=linux-hello replacement=403 effect=1 kind=write binding_epoch=1' \
    'LINUX_CODE_PAGER Commit workload=linux-hello replacement=412 effect=3 binding_epoch=1' \
    'backend_replayed=true' \
    'output_publications=2' \
    'wake_publications=2' \
    'resume_returns=2' \
    'entry_publication=eager' \
    'permissions=RWX' \
    'wx=true' \
    'linux_timeout=true' \
    'etimedout=true' \
    'ecanceled=true' \
    'LINUX_FUTEX GuestResume scenario=expire' \
    'GUEST_FAIL' \
    'Linux personality rejected an unexpected Linux syscall snapshot' \
    'unknown Linux personality' \
    'unknown Linux code pager' \
    'panicked at' \
    'Non-resettable panic!'; do
    if grep -Fq "$forbidden" "$log"; then
        echo "forbidden serial evidence: $forbidden" >&2
        exit 1
    fi
done

if grep -Eiq '(^|[[:space:]])panic([!:.[:space:]]|$)|panicked at' "$log"; then
    echo "forbidden serial evidence: panic" >&2
    exit 1
fi

if awk '
    { sub(/\r$/, "") }
    /^LINUX_FUTEX_SLICE BEGIN / { bounded = 1 }
    bounded && tolower($0) ~ /(^|[^[:alnum:]_])(requeue|clone)([^[:alnum:]_]|$)/ { found = 1 }
    /^LINUX_FUTEX_SLICE PASS / { bounded = 0 }
    END { exit found ? 0 : 1 }
' "$log"; then
    echo "forbidden Stage 6B.1 serial evidence: requeue or clone" >&2
    exit 1
fi

echo "serial assertions: PASS"
