# SPDX-License-Identifier: MPL-2.0

# Strict one-log oracle for the bounded OSTD composition receipt. Every
# composition line is part of the contract: missing, reordered, mutated, or
# additional evidence is rejected.

function fail(message) {
    print "composition trace assertion failed: " message > "/dev/stderr"
    failed = 1
    exit 1
}

BEGIN {
    expected[++total] = "COMPOSITION_SLICE BEGIN root_scope=70 authority_epoch=121 domains=5 bounded=true single_cpu=true runtime_fs=false runtime_net=false virtio_adapter=external_stage5b_consistency"
    expected[++total] = "COMPOSITION_DERIVE Reject root_scope=70 domain=personality reason=StaleAuthority failure_atomic=true mutation=false"
    expected[++total] = "COMPOSITION_DERIVE Applied root_scope=70 domain_scope=73 domain=personality effect=1 parent=root authority_epoch=121 binding_epoch=2 device_generation=none credit_class=1 units=1 edge_indexed=true effect_indexed=true local_scope_indexed=true failure_atomic=true"
    expected[++total] = "COMPOSITION_DERIVE Reject root_scope=70 domain=pager parent=personality presented_parent_binding_epoch=1 current_parent_binding_epoch=2 reason=StaleParentEnvelope failure_atomic=true mutation=false"
    expected[++total] = "COMPOSITION_DERIVE Reject root_scope=70 domain=pager parent=personality presented_binding_epoch=1 current_binding_epoch=2 reason=StaleTargetEnvelope failure_atomic=true mutation=false"
    expected[++total] = "COMPOSITION_DERIVE Applied root_scope=70 domain_scope=72 domain=pager effect=2 parent=personality authority_epoch=121 binding_epoch=2 device_generation=none credit_class=2 units=1 edge_indexed=true effect_indexed=true local_scope_indexed=true failure_atomic=true"
    expected[++total] = "COMPOSITION_DERIVE Applied root_scope=70 domain_scope=71 domain=scheduler effect=3 parent=pager authority_epoch=121 binding_epoch=4 device_generation=none credit_class=3 units=1 edge_indexed=true effect_indexed=true local_scope_indexed=true failure_atomic=true"
    expected[++total] = "COMPOSITION_DERIVE Applied root_scope=70 domain_scope=74 domain=readiness effect=4 parent=personality authority_epoch=121 binding_epoch=2 device_generation=none credit_class=4 units=1 edge_indexed=true effect_indexed=true local_scope_indexed=true failure_atomic=true"
    expected[++total] = "COMPOSITION_DERIVE Applied root_scope=70 domain_scope=75 domain=virtio effect=5 parent=readiness authority_epoch=121 binding_epoch=3 device_generation=3 credit_class=5 units=1 edge_indexed=true effect_indexed=true local_scope_indexed=true failure_atomic=true"
    expected[++total] = "COMPOSITION_BACKBONE Active root_scope=70 authority_epoch=121 domains=5 causal_nodes=6 causal_edges=5 delegated_credits=5 reverse_effects=5 reverse_local_scopes=5 gate=single"
    expected[++total] = "COMPOSITION_BINDING Attach root_scope=70 domain_scope=73 domain=personality binding_epoch=2 device_generation=none independent=true"
    expected[++total] = "COMPOSITION_BINDING Attach root_scope=70 domain_scope=72 domain=pager binding_epoch=2 device_generation=none independent=true"
    expected[++total] = "COMPOSITION_BINDING Attach root_scope=70 domain_scope=71 domain=scheduler binding_epoch=4 device_generation=none independent=true"
    expected[++total] = "COMPOSITION_BINDING Attach root_scope=70 domain_scope=74 domain=readiness binding_epoch=2 device_generation=none independent=true"
    expected[++total] = "COMPOSITION_BINDING Attach root_scope=70 domain_scope=75 domain=virtio binding_epoch=3 device_generation=3 independent=true"
    expected[++total] = "COMPOSITION_READINESS Receipt domain_scope=74 effect=4 delivery_sequence=1 events=1 binding_epoch=2 replay_rejected=true live_sources=0 live_sets=0 subscriptions=0 queued=0 unpublished=0"
    expected[++total] = "COMPOSITION_VIRTIO Adapter domain_scope=75 effect=5 source=external_stage5b_consistency binding_epoch=3 device_generation=3 commit_point=avail_idx_release reset_timeout=tombstone iotlb_completion_before_release=true identity_preserving=false"
    expected[++total] = "COMPOSITION_VIRTIO Commit root_scope=70 domain_scope=75 effect=5 binding_epoch=3 device_generation=3 commit_sequence=1 point=avail_idx_release"
    expected[++total] = "COMPOSITION_REVOKE Begin root_scope=70 authority_epoch_old=121 authority_epoch_new=122 frozen_domains=5 frozen_effects=5 cohort_source=registry_live_selection gate=closed"
    expected[++total] = "COMPOSITION_REJECT stage=closing kind=stale_child domain=scheduler presented_authority_epoch=121 current_authority_epoch=122 mutation=false"
    expected[++total] = "COMPOSITION_REJECT stage=closing kind=stale_commit domain=scheduler effect=3 presented_authority_epoch=121 current_authority_epoch=122 mutation=false"
    expected[++total] = "COMPOSITION_REJECT stage=closing kind=stale_receipt domain=virtio presented_binding_epoch=2 current_binding_epoch=3 presented_device_generation=2 current_device_generation=3 mutation=false"
    expected[++total] = "COMPOSITION_REVOKE Pending root_scope=70 reason=domain_closure_receipts_incomplete live=5 credits_free=0 accepted_receipts=0"
    expected[++total] = "COMPOSITION_REJECT stage=closing kind=live_descendant domain=personality live_children=pager+readiness child_first=true mutation=false"
    expected[++total] = "COMPOSITION_CLOSURE Issue root_scope=70 domain_scope=71 domain=scheduler effect=3 receipt_sequence=1 receipt_revision=1 domain_revision=1 revoke_sequence=1 terminal_sequence=1 binding_epoch=4 device_generation=none disposition=Abort outcome=Aborted status=Closed publication_pending=true"
    expected[++total] = "COMPOSITION_RECEIPT REJECT stage=accept kind=stale domain=scheduler receipt_sequence=1 presented_authority_epoch=121 current_authority_epoch=122 failure_atomic=true mutation=false"
    expected[++total] = "COMPOSITION_RECEIPT REJECT stage=accept kind=out_of_order domain=scheduler presented_sequence=2 expected_sequence=1 result=OutOfOrderReceipt failure_atomic=true mutation=false"
    expected[++total] = "COMPOSITION_CLOSURE Accept root_scope=70 domain=scheduler effect=3 receipt_sequence=1 receipt_revision=1 status=Closed acknowledgement=Applied credit=Free"
    expected[++total] = "COMPOSITION_RECEIPT REJECT stage=accept kind=duplicate domain=scheduler receipt_sequence=1 result=DuplicateReceipt failure_atomic=true mutation=false"
    expected[++total] = "COMPOSITION_CLOSURE Issue root_scope=70 domain_scope=72 domain=pager effect=2 receipt_sequence=2 receipt_revision=2 domain_revision=1 revoke_sequence=1 terminal_sequence=2 binding_epoch=2 device_generation=none disposition=Abort outcome=Aborted status=Closed publication_pending=true"
    expected[++total] = "COMPOSITION_CLOSURE Accept root_scope=70 domain=pager effect=2 receipt_sequence=2 receipt_revision=2 status=Closed acknowledgement=Applied credit=Free"
    expected[++total] = "COMPOSITION_VIRTIO Timeout root_scope=70 domain_scope=75 effect=5 binding_epoch=3 device_generation=3 tombstone=1 retained_credit_class=5 retained_units=1 owners_retained=true status=TimedOut"
    expected[++total] = "COMPOSITION_RECEIPT Issue root_scope=70 domain=virtio effect=5 receipt_sequence=3 receipt_revision=3 domain_revision=1 revoke_sequence=1 binding_epoch=3 device_generation=3 status=TimedOut effect_live=true credit_live=true"
    expected[++total] = "COMPOSITION_RECEIPT Accept root_scope=70 domain=virtio effect=5 receipt_sequence=3 receipt_revision=3 domain_revision=1 status=TimedOut root_state=Closing effect_live=true credit_live=true"
    expected[++total] = "COMPOSITION_REVOKE TimedOut root_scope=70 domain=virtio receipt_sequence=3 receipt_revision=3 domain_revision=1 result=RevokeTimedOut root_state=Closing effect_live=true credit_live=true closure_receipts=2"
    expected[++total] = "COMPOSITION_VIRTIO Retry root_scope=70 domain_scope=75 effect=5 tombstone=1 attempt=1 domain_revision_before=1 domain_revision_after=2 invalidated_receipt_sequence=3 device_generation_before=3 device_generation_after=4 external_reset_ack_observed=true external_iotlb_complete_observed=true evidence_relation=component_consistency identity_preserving=false credit_retained_until_close=true tombstone_invalidated=true"
    expected[++total] = "COMPOSITION_RECEIPT REJECT stage=retry kind=stale_timeout_replay domain=virtio receipt_sequence=3 presented_domain_revision=1 current_domain_revision=2 result=StaleClosureReceipt failure_atomic=true mutation=false"
    expected[++total] = "COMPOSITION_CLOSURE Issue root_scope=70 domain_scope=75 domain=virtio effect=5 receipt_sequence=4 receipt_revision=4 domain_revision=2 revoke_sequence=1 terminal_sequence=3 binding_epoch=3 device_generation=4 disposition=Drain outcome=Completed status=Closed publication_pending=true"
    expected[++total] = "COMPOSITION_CLOSURE Accept root_scope=70 domain=virtio effect=5 receipt_sequence=4 receipt_revision=4 status=Closed acknowledgement=Applied credit=Free"
    expected[++total] = "COMPOSITION_CLOSURE Issue root_scope=70 domain_scope=74 domain=readiness effect=4 receipt_sequence=5 receipt_revision=5 domain_revision=1 revoke_sequence=1 terminal_sequence=4 binding_epoch=2 device_generation=none disposition=Abort outcome=Aborted status=Closed publication_pending=true"
    expected[++total] = "COMPOSITION_CLOSURE Accept root_scope=70 domain=readiness effect=4 receipt_sequence=5 receipt_revision=5 status=Closed acknowledgement=Applied credit=Free"
    expected[++total] = "COMPOSITION_CLOSURE Issue root_scope=70 domain_scope=73 domain=personality effect=1 receipt_sequence=6 receipt_revision=6 domain_revision=1 revoke_sequence=1 terminal_sequence=5 binding_epoch=2 device_generation=none disposition=Abort outcome=Aborted status=Closed publication_pending=true"
    expected[++total] = "COMPOSITION_CLOSURE Accept root_scope=70 domain=personality effect=1 receipt_sequence=6 receipt_revision=6 status=Closed acknowledgement=Applied credit=Free"
    expected[++total] = "COMPOSITION_REVOKE Complete root_scope=70 authority_epoch=122 frozen_domains=5 closure_receipts=5 accepted_receipts=6 invalidated_receipts=1 receipt_revision=6 credits_free=5 live=0 pending=0 state=Revoked"
    expected[++total] = "COMPOSITION_SLICE PASS root_scope=70 authority_epoch_old=121 authority_epoch_new=122 domains=5 causal_nodes=6 causal_edges=5 parent_chain_immutable=true stale_parent_rejected=true stale_target_rejected=true delegated_credits=5 binding_epochs=scheduler:4,pager:2,personality:2,readiness:2,virtio:3 device_generations=virtio:3->4 frozen_domains=5 cohort_source=registry_live_selection closure_order=scheduler,pager,virtio,readiness,personality child_first=true live_descendant_rejected=true closure_receipts=5 receipt_sequences=6 receipt_revision=6 receipt_acceptance=authoritative closure_sequences_unique=true timeout_receipts=1 timeout_replay_rejected=true duplicate_receipt_rejected=true out_of_order_receipt_rejected=true virtio_tombstones=1 virtio_retries=1 stale_child_rejected=true stale_commit_rejected=true stale_receipt_rejected=true virtio_evidence=component_consistency identity_preserving=false credits_free=5 live=0 pending=0 final_quiescent=true bounded=true single_cpu=true runtime_fs=false runtime_net=false"
}

{
    sub(/\r$/, "")
}

/^COMPOSITION_/ {
    seen++
    if (seen > total)
        fail("unexpected additional receipt: " $0)
    if ($0 != expected[seen])
        fail("receipt " seen " mismatch; expected [" expected[seen] "] observed [" $0 "]")
}

END {
    if (failed)
        exit 1
    if (seen != total)
        fail("expected " total " receipts, observed " seen)
}
