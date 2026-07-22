# Validate the exact unchanged Stage 6 runtime-filesystem execution and its
# bounded lifecycle companion. Scheduler and other workload noise is ignored;
# every filesystem-relevant receipt must occur exactly once and in order.

function fail(message) {
    print "runtime filesystem assertion failed at serial line " NR ": " message > "/dev/stderr"
    failed = 1
    exit 1
}

function expect(line) {
    expected[++expected_count] = line
}

BEGIN {
    expect("FILESYSTEM_LIFECYCLE BEGIN authority_epoch=201 personality_binding=1 pager_binding=7 filesystem_binding=1 block_binding=3 device_generation=3 epochs_independent=true bounded=true real_dma=false")
    expect("FILESYSTEM_LIFECYCLE PagerCrash old_binding=7 new_binding=8 snapshot=true ready=true adopted=true mapping_publications=1 address_space_generation=1->2 peer_epochs_unchanged=true stale_old_token=StaleBinding full_projection_unchanged=true")
    expect("FILESYSTEM_LIFECYCLE PrecommitCrash domain=filesystem effect=1 old_binding=1 new_binding=2 snapshot=true ready=true adopted=true peer_epochs_unchanged=true stale_old_handle=StaleBinding registry_and_domain_projection_unchanged=true result=4 quiescent=true")
    expect("FILESYSTEM_LIFECYCLE PostcommitCrash domain=personality effect=1 old_binding=1 new_binding=2 commit_sequence=1 kernel_completion=true reply_publications=1 peer_epochs_unchanged=true late_service_rejected=StaleBinding registry_and_domain_projection_unchanged=true duplicate_terminal=false quiescent=true")
    expect("FILESYSTEM_LIFECYCLE PwriteRace winner=commit commit_sequence=1 revoke_disposition=Drain inode_before=00000000 inode_after=00007879 pwrite_publications=1 stale_commit=StaleAuthority registry_effect_inode_projection_unchanged=true publication_acked=true quiescent=true")
    expect("FILESYSTEM_LIFECYCLE PwriteRace winner=revoke revoke_disposition=Abort inode_before=00000000 inode_after=00000000 pwrite_publications=0 stale_commit=StaleAuthority registry_effect_inode_projection_unchanged=true publication_acked=true quiescent=true")
    expect("FILESYSTEM_LIFECYCLE ResetTimeout old_binding=3 new_binding=4 device_generation=3 unchanged_until_reset_ack=true tombstone=1 owners_retained=3 stale_completion=StaleToken full_projection_unchanged=true real_dma=false")
    expect("FILESYSTEM_LIFECYCLE ResetAck tombstone=1 device_generation=3->4 reset_ack=true owners_retained=3 iotlb_required=true")
    expect("FILESYSTEM_LIFECYCLE IotlbTimeout binding=4 device_generation=4 tombstone=2 owners_retained=3 stale_reset_tombstone=StaleTombstone full_projection_unchanged=true real_dma=false")
    expect("FILESYSTEM_LIFECYCLE IotlbAck tombstone=2 binding=4 device_generation=4 iotlb_ack=true owners_released=3 phase=Released")
    expect("FILESYSTEM_LIFECYCLE PASS pager_crash_adopt=true precommit_adopt=true postcommit_fence=true pwrite_commit_first=true pwrite_revoke_first=true reset_timeout_tombstone=true iotlb_timeout_tombstone=true device_generation_after_reset_ack=true owners_retained_until_iotlb_ack=true stale_token_full_projection_unchanged=true personality_epoch_independent=true pager_epoch_independent=true filesystem_epoch_independent=true block_epoch_independent=true quiescent=true bounded=true real_dma=false")
    expect("LINUX_FS_SLICE BEGIN workload=linux-runtime-fs-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=14 registry=production_shared root_scope=95 domains=3 typed_credit_classes=7 filesystem=bounded_in_memory pager=bounded block=deterministic_preparation smp=1")
    expect("LINUX_FS_ARTIFACT source_sha256=c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f elf_sha256=0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef first_pread_input_sha256=a101969acc8dac3209f8be33a5d070e5972fc82f49f5ef85e28db576068024fc first_pread_payload_sha256=3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359 block_preparation_sha256=e3229d4050798eedcd6503e8b44c3e6bad6d1c105f07f79d3f4fbb04925f1f14 sector_sha256=9cb83be92a4c9239752718e6e20ac00fe9e32842ea561ae7fedec94b620a05cc full_image_sha256=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 sector_fnv1a=0xc4b4ad9059afd22e relation=component_consistency real_stage5b_required=true same_boot=false identity_preserving_stage5b=false")
    expect("LINUX_FS Open effect=1 commit_sequence=1 fd=3 path=/bin/linux-runtime-fs-smoke kind=executable")
    expect("LINUX_FS_PRODUCTION_IDENTITY Capture root_scope=95 authority_epoch=141 cohort_source=normal_pread64_path registry=workload_owned syscall_effect=2 syscall_domain=personality filesystem_effect=3 filesystem_domain=filesystem block_effect=4 block_domain=block immutable_ancestry=syscall->filesystem->block distinct_effects=true capture_after_input_validation=true capture_before_payload_read=true")
    expect("LINUX_FS_PRODUCTION_IDENTITY Recovery filesystem_binding=1->2 crash_injection=registry_domain real_user_service_crash=false crash_cohort=filesystem_read_only snapshot=true ready=true rebind=true adopted_same_effect=true parent_unchanged=true origin_binding_unchanged=true resources_unchanged=true old_handle=StaleBinding full_projection_unchanged=true peer_bindings_unchanged=true")
    expect("LINUX_FS_PRODUCTION_IDENTITY Ledger credit_classes=control:0x301,filesystem:0x302,queue:0x303,pinned_page:0x304,dma_mapping:0x305,guest_reply:0x306,block_preparation:0x307 capacity=7 held_at_preparation=4 device_credits_held=0 device_credits_free=queue+pinned_page+dma_mapping resources=syscall:0x7100:1:1+0x7300:1:1,filesystem:0x7101:1:1+0x7301:1:1,block_preparation:0x7302:1:1+0x7306:1:1 exact_generations=true")
    expect("LINUX_FS_PRODUCTION_IDENTITY Digests input_sha256=a101969acc8dac3209f8be33a5d070e5972fc82f49f5ef85e28db576068024fc payload_sha256=3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359 preparation_sha256=e3229d4050798eedcd6503e8b44c3e6bad6d1c105f07f79d3f4fbb04925f1f14 input_bytes=64 payload_bytes=4 preparation_bytes=98 runtime_fnv_checked=true")
    expect("LINUX_FS_PRODUCTION_IDENTITY BlockPreparation effect=4 phase=Prepared terminal=Aborted terminal_sequence=2 preparation_only=true adapter=bounded_in_memory queue_credit_held=false pinned_page_credit_held=false dma_mapping_credit_held=false device_commit=false avail_idx_release=false returned_payload_source=runtime_fs_elf")
    expect("LINUX_FS_PRODUCTION_IDENTITY NoSyntheticCohort positive_cohort=normal_workload_path foreign_registry_receipt=CommitConflict foreign_receipt_accepted=false full_projection_unchanged=true negative_only_registry=true")
    expect("LINUX_FS_PRODUCTION_IDENTITY Close block_terminal_sequence=2 filesystem_commit_sequence=2 filesystem_terminal_sequence=3 personality_commit_sequence=3 leaf_first=true descendants_closed_before_parent_commit=true filesystem_result_source=bounded_in_memory")
    expect("LINUX_FS Pread effect=2 commit_sequence=3 fd=3 offset=0 bytes=4 elf_magic=true pager=bounded block_preparation=observed device_commit=false payload_source=bounded_in_memory")
    expect("LINUX_FS Statx effect=5 commit_sequence=4 mask=0x17ff mode=regular size=10232 empty_path=true")
    expect("LINUX_FS Newfstatat effect=6 commit_sequence=5 mode=regular size=10232 empty_path=true")
    expect("LINUX_FS Open effect=7 commit_sequence=6 fd=4 path=/tmp/runtime-fs.bin kind=regular create=true truncate=true mode=0644")
    expect("LINUX_FS Pwrite effect=8 commit_sequence=7 fd=4 offset=2 bytes=2 payload=7879 state_after=00007879 commit_before_mutation=true dma=false")
    expect("LINUX_FS Pread effect=9 commit_sequence=8 fd=4 offset=0 bytes=4 payload=00007879")
    expect("LINUX_FS Open effect=10 commit_sequence=9 fd=5 path=/proc/self kind=proc_directory")
    expect("LINUX_FS Readlinkat effect=11 commit_sequence=10 dirfd=5 path=exe target=/bin/linux-runtime-fs-smoke bytes=27 nul_appended=false")
    expect("LINUX_FS Close effect=12 commit_sequence=11 fd=5 remaining_runtime_fds=2")
    expect("LINUX_FS Close effect=13 commit_sequence=12 fd=4 remaining_runtime_fds=1")
    expect("LINUX_FS Close effect=14 commit_sequence=13 fd=3 remaining_runtime_fds=0")
    expect("LINUX_FS Write effect=15 commit_sequence=14 fd=1 bytes=14 stdout_exact=true")
    expect("LINUX_FS stdout=runtime fs ok")
    expect("LINUX_FS Exit effect=16 commit_sequence=15 status=0 syscall=exit resumed_after_exit=false")
    expect("EFFECT_REGISTRY Quiescent workload=linux-runtime-fs production_root=95 production_effects=16 live=0 pending_publications=0 credits=Free")
    expect("LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=14 openat=3 pread64=2 statx=1 newfstatat=1 pwrite64=1 readlinkat=1 close=3 write=1 exit=1 commit_gate=true publication_acks=14 production_root=true production_domains=3 production_effects=16 production_identity_preparation=true immutable_ancestry=true filesystem_registry_domain_crash_adopt=true real_user_service_crash=false no_synthetic_cohort=true typed_credit_classes=7 leaf_first=true registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true block_adapter=bounded_in_memory block_preparation_observed=true device_commit=false real_dma=false virtio_evidence=component_consistency same_boot=false identity_preserving_stage5b=false")
}

{
    sub(/\r$/, "")
    relevant = ($0 ~ /^FILESYSTEM_LIFECYCLE / ||
                $0 ~ /^LINUX_FS( |_)/ ||
                $0 ~ /^EFFECT_REGISTRY Quiescent workload=linux-runtime-fs /)
    if (!relevant)
        next

    observed++
    if (observed > expected_count)
        fail("unexpected additional receipt: " $0)
    if ($0 != expected[observed])
        fail("receipt #" observed " mismatch; expected: " expected[observed] "; observed: " $0)
}

END {
    if (failed)
        exit 1
    if (observed != expected_count)
        fail("expected " expected_count " receipts, observed " observed)
}
