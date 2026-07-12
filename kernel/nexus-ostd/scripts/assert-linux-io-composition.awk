# SPDX-License-Identifier: MPL-2.0

# Strict one-log oracle for the additive seven-domain Linux I/O composition
# receipt. Every line under the new prefix is contractual: missing, reordered,
# mutated, duplicated, or additional evidence is rejected. The frozen
# COMPOSITION_* predecessor remains outside this oracle.

function fail(message) {
    print "linux I/O composition trace assertion failed: " message > "/dev/stderr"
    failed = 1
    exit 1
}

BEGIN {
    expected[++total] = "LINUX_IO_COMPOSITION BEGIN root_scope=120 authority_epoch=401 domains=7 effects=9 causal_nodes=10 causal_edges=9 credit_classes=8 credit_units=9 control_capacity=2 bounded=true single_cpu=true same_boot_kernel_adapters=true retained_workload_identity=false retained_effects_in_root_cohort=false registry_multi_domain_binding=false stage5b_relation=component_consistency stage5b_same_boot=false identity_preserving_stage5b=false"
    expected[++total] = "LINUX_IO_COMPOSITION PREREQUISITE retained_fs_scope=95 retained_fs_state=Revoked retained_fs_authority_epoch=141->142 retained_fs_terminalizations=14 retained_fs_publication_acks=14 retained_fs_quiescent=true retained_net_scope=105 retained_net_state=Revoked retained_net_authority_epoch=241->242 retained_net_terminalizations=22 retained_net_publication_acks=22 retained_net_quiescent=true retained_workloads_same_boot=true relation=prior_receipts_only retained_workload_identity=false retained_effects_in_root_cohort=false"
    expected[++total] = "LINUX_IO_COMPOSITION BINDINGS scheduler=4 pager=2 personality=2 filesystem=2 virtio=3 network=2 readiness=2 envelopes=bounded_outer_state registry_multi_domain_binding=false"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Reject presented_authority_epoch=400 current_authority_epoch=401 reason=StaleAuthority failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=1 kind=FsSyscall domain=personality parent=Root authority_epoch=401 binding_epoch=2 generation=none credit=Control units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=2 kind=NetSyscall domain=personality parent=Root authority_epoch=401 binding_epoch=2 generation=none credit=Control units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=3 kind=PagerMap domain=pager parent=FsSyscall authority_epoch=401 binding_epoch=2 generation=address_space:2 credit=Memory units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=4 kind=SchedulerAction domain=scheduler parent=PagerMap authority_epoch=401 binding_epoch=4 generation=none credit=Scheduling units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=5 kind=FsOp domain=filesystem parent=FsSyscall authority_epoch=401 binding_epoch=2 generation=inode:1 credit=Filesystem units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=6 kind=BlockReq domain=virtio parent=FsOp authority_epoch=401 binding_epoch=3 generation=device:3 credit=DMA units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=7 kind=NetOp domain=network parent=NetSyscall authority_epoch=401 binding_epoch=2 generation=socket:1 credit=Network units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=8 kind=ReadinessWait domain=readiness parent=NetOp authority_epoch=401 binding_epoch=2 generation=source:1 credit=Readiness units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect=9 kind=BufferLease domain=network parent=NetOp authority_epoch=401 binding_epoch=2 generation=socket:1 credit=Buffer units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true"
    expected[++total] = "LINUX_IO_COMPOSITION ACTIVE root_scope=120 authority_epoch=401 domains=7 effects=9 causal_nodes=10 causal_edges=9 domain_effect_counts=personality:2,pager:1,scheduler:1,filesystem:1,virtio:1,network:2,readiness:1 credit_classes=8 credit_units=9 control_capacity=2 reverse_effects=9 reverse_domains=7 gate=single"
    expected[++total] = "LINUX_IO_COMPOSITION FS Commit effect=5 commit_sequence=1 inode_before=00000000 inode_after=00007879 commit_before_mutation=true guest_reply=false adapter=bounded_in_memory"
    expected[++total] = "LINUX_IO_COMPOSITION VIRTIO Adapter effect=6 source=external_stage5b_consistency binding_epoch=3 device_generation=3 commit_point=avail_idx_release reset_timeout=tombstone iotlb_completion_before_release=true real_dma_primary=false stage5b_relation=component_consistency stage5b_same_boot=false identity_preserving_stage5b=false"
    expected[++total] = "LINUX_IO_COMPOSITION VIRTIO Commit effect=6 commit_sequence=2 binding_epoch=3 device_generation=3 point=avail_idx_release credit=DMA:Held"
    expected[++total] = "LINUX_IO_COMPOSITION NETWORK Commit effects=7,9 commit_sequences=3,4 atomic_batch=true net_publication=Applied buffer_visibility=ping buffer_credit=Held guest_reply=false adapter=bounded_loopback"
    expected[++total] = "LINUX_IO_COMPOSITION READINESS Reject causal_effect=9 causal_commit_sequence=4 expected_effect=7 expected_commit_sequence=3 result=InvalidState failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION READINESS Commit effect=8 commit_sequence=5 causal_net_effect=7 causal_net_commit_sequence=3 exact_net_receipt=true kernel_owned=true"
    expected[++total] = "LINUX_IO_COMPOSITION READINESS Delivery effect=8 delivery_sequence=1 events=1 replay_rejected=true live_sources=0 live_sets=0 subscriptions=0 queued=0 unpublished=0"
    expected[++total] = "LINUX_IO_COMPOSITION GUEST_REPLIES fs=0 net=0 syscall_effects=1,2 phases=Registered commit_gate=true"
    expected[++total] = "LINUX_IO_COMPOSITION REVOKE Begin root_scope=120 authority_epoch_old=401 authority_epoch_new=402 frozen_domains=7 frozen_effects=9 frozen_credit_units=9 cohort_source=registry_live_selection gate=closed"
    expected[++total] = "LINUX_IO_COMPOSITION REJECT stage=closing kind=stale_derive presented_authority_epoch=401 current_authority_epoch=402 result=StaleAuthority mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION REJECT stage=closing kind=stale_commit effect=4 presented_authority_epoch=401 current_authority_epoch=402 result=StaleAuthority mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION REJECT stage=closing kind=live_descendant effect=1 children=3,5 result=LiveDescendant child_first=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION REJECT stage=closing kind=live_descendant effect=2 children=7 result=LiveDescendant child_first=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=scheduler effect=4 kind=SchedulerAction terminal_sequence=1 outcome=Aborted publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=pager effect=3 kind=PagerMap terminal_sequence=2 outcome=Aborted publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Reject kind=live_child_receipt domain=pager child_domain=scheduler result=LiveDescendant failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=scheduler effects=4 terminal_sequences=1 receipt_sequence=1 receipt_revision=1 authority_epoch=402 binding_epoch=4 device_generation=none status=Closed credits=Scheduling:1 credit_units=1"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Reject kind=stale domain=scheduler receipt_sequence=1 presented_authority_epoch=401 current_authority_epoch=402 result=StaleReceipt failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Reject kind=out_of_order domain=scheduler presented_sequence=2 expected_sequence=1 result=OutOfOrderReceipt failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=scheduler receipt_sequence=1 receipt_revision=1 status=Closed acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Reject kind=duplicate domain=scheduler receipt_sequence=1 result=DuplicateReceipt failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Reject kind=duplicate_issue domain=scheduler result=DuplicateReceipt failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=pager effects=3 terminal_sequences=2 receipt_sequence=2 receipt_revision=2 authority_epoch=402 binding_epoch=2 device_generation=none status=Closed credits=Memory:1 credit_units=1"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=pager receipt_sequence=2 receipt_revision=2 status=Closed acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION VIRTIO Timeout effect=6 binding_epoch=3 device_generation=3 tombstone=1 owners_retained=true dma_credit=Held effect_live=true"
    expected[++total] = "LINUX_IO_COMPOSITION VIRTIO Reject action=Terminalize effect=6 tombstone=1 result=TombstoneActive owners_retained=true dma_credit=Held failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=virtio effects=6 terminal_sequences=none receipt_sequence=3 receipt_revision=3 authority_epoch=402 binding_epoch=3 device_generation=3 status=TimedOut credits=DMA:1 credit_units=1"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=virtio receipt_sequence=3 receipt_revision=3 status=TimedOut acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION REVOKE TimedOut domain=virtio receipt_sequence=3 receipt_revision=3 root_state=Closing effect_live=true credit_live=true closure_receipts=2"
    expected[++total] = "LINUX_IO_COMPOSITION VIRTIO Retry effect=6 tombstone=1 attempt=1 invalidated_receipt_sequence=3 device_generation_before=3 device_generation_after=4 reset_ack=true iotlb_complete=true evidence_relation=component_consistency identity_preserving=false credit_retained_until_close=true"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Reject kind=stale_timeout_replay domain=virtio receipt_sequence=3 presented_device_generation=3 current_device_generation=4 result=StaleReceipt failure_atomic=true mutation=false"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=virtio effect=6 kind=BlockReq terminal_sequence=3 outcome=Completed publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=virtio effects=6 terminal_sequences=3 receipt_sequence=4 receipt_revision=4 authority_epoch=402 binding_epoch=3 device_generation=4 status=Closed credits=DMA:1 credit_units=1"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=virtio receipt_sequence=4 receipt_revision=4 status=Closed acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=filesystem effect=5 kind=FsOp terminal_sequence=4 outcome=Completed publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=filesystem effects=5 terminal_sequences=4 receipt_sequence=5 receipt_revision=5 authority_epoch=402 binding_epoch=2 device_generation=none status=Closed credits=Filesystem:1 credit_units=1"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=filesystem receipt_sequence=5 receipt_revision=5 status=Closed acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=readiness effect=8 kind=ReadinessWait terminal_sequence=5 outcome=Completed publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=readiness effects=8 terminal_sequences=5 receipt_sequence=6 receipt_revision=6 authority_epoch=402 binding_epoch=2 device_generation=none status=Closed credits=Readiness:1 credit_units=1"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=readiness receipt_sequence=6 receipt_revision=6 status=Closed acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=network effect=9 kind=BufferLease terminal_sequence=6 outcome=Completed publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=network effect=7 kind=NetOp terminal_sequence=7 outcome=Completed publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=network effects=7,9 terminal_sequences=6,7 receipt_sequence=7 receipt_revision=7 authority_epoch=402 binding_epoch=2 device_generation=none status=Closed credits=Network+Buffer:2 credit_units=2"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=network receipt_sequence=7 receipt_revision=7 status=Closed acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=personality effect=1 kind=FsSyscall terminal_sequence=8 outcome=Aborted publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION TERMINAL domain=personality effect=2 kind=NetSyscall terminal_sequence=9 outcome=Aborted publication_ack=Applied credit=Free"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Issue domain=personality effects=1,2 terminal_sequences=8,9 receipt_sequence=8 receipt_revision=8 authority_epoch=402 binding_epoch=2 device_generation=none status=Closed credits=Control:2 credit_units=2"
    expected[++total] = "LINUX_IO_COMPOSITION RECEIPT Accept domain=personality receipt_sequence=8 receipt_revision=8 status=Closed acknowledgement=Applied"
    expected[++total] = "LINUX_IO_COMPOSITION REVOKE Complete root_scope=120 authority_epoch=402 frozen_domains=7 frozen_effects=9 closure_receipts=7 accepted_receipts=8 invalidated_receipts=1 effect_terminalizations=9 receipt_revision=8 credits_free=9 live=0 pending=0 state=Revoked"
    expected[++total] = "LINUX_IO_COMPOSITION PASS domains=7 effects=9 causal_nodes=10 causal_edges=9 credit_classes=8 credit_units=9 control_capacity=2 effect_terminalizations=9 closure_receipts=7 accepted_receipts=8 invalidated_receipts=1 receipt_revision=8 credits_free=9 fs_replies=0 net_replies=0 buffer_closure_drains=1 retained_workloads_same_boot=true retained_workload_identity=false retained_effects_in_root_cohort=false registry_multi_domain_binding=false domain_binding_envelopes=bounded_outer_state stage5b_relation=component_consistency stage5b_same_boot=false identity_preserving_stage5b=false real_dma_primary=false smoltcp=false virtio_net=false external_packets=false tcp_breadth=false cross_fd_total_order=false bounded=true single_cpu=true"
}

{
    sub(/\r$/, "")

    if ($0 ~ /^LINUX_IO_COMPOSITION /) {
        seen++
        if (seen > total)
            fail("unexpected additional receipt: " $0)
        if ($0 != expected[seen])
            fail("receipt " seen " mismatch; expected [" expected[seen] "] observed [" $0 "]")
    }
}

END {
    if (failed)
        exit 1
    if (NR == 0)
        exit 0
    if (seen != total)
        fail("expected " total " receipts, observed " (seen + 0))
}
