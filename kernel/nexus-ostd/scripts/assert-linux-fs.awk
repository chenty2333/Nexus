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
    expect("LINUX_FS_SLICE BEGIN workload=linux-runtime-fs-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=14 registry=common filesystem=bounded_in_memory pager=bounded block=component_consistency smp=1")
    expect("LINUX_FS_ARTIFACT source_sha256=c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f elf_sha256=0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef sector_sha256=9cb83be92a4c9239752718e6e20ac00fe9e32842ea561ae7fedec94b620a05cc full_image_sha256=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 sector_fnv1a=0xc4b4ad9059afd22e relation=component_consistency real_stage5b_required=true same_boot=false identity_preserving=false")
    expect("LINUX_FS Open effect=1 commit_sequence=1 fd=3 path=/bin/linux-runtime-fs-smoke kind=executable")
    expect("LINUX_FS Pread effect=2 commit_sequence=2 fd=3 offset=0 bytes=4 elf_magic=true pager=bounded block_fixture=component_consistency")
    expect("LINUX_FS Statx effect=3 commit_sequence=3 mask=0x17ff mode=regular size=10232 empty_path=true")
    expect("LINUX_FS Newfstatat effect=4 commit_sequence=4 mode=regular size=10232 empty_path=true")
    expect("LINUX_FS Open effect=5 commit_sequence=5 fd=4 path=/tmp/runtime-fs.bin kind=regular create=true truncate=true mode=0644")
    expect("LINUX_FS Pwrite effect=6 commit_sequence=6 fd=4 offset=2 bytes=2 payload=7879 state_after=00007879 commit_before_mutation=true dma=false")
    expect("LINUX_FS Pread effect=7 commit_sequence=7 fd=4 offset=0 bytes=4 payload=00007879")
    expect("LINUX_FS Open effect=8 commit_sequence=8 fd=5 path=/proc/self kind=proc_directory")
    expect("LINUX_FS Readlinkat effect=9 commit_sequence=9 dirfd=5 path=exe target=/bin/linux-runtime-fs-smoke bytes=27 nul_appended=false")
    expect("LINUX_FS Close effect=10 commit_sequence=10 fd=5 remaining_runtime_fds=2")
    expect("LINUX_FS Close effect=11 commit_sequence=11 fd=4 remaining_runtime_fds=1")
    expect("LINUX_FS Close effect=12 commit_sequence=12 fd=3 remaining_runtime_fds=0")
    expect("LINUX_FS Write effect=13 commit_sequence=13 fd=1 bytes=14 stdout_exact=true")
    expect("LINUX_FS stdout=runtime fs ok")
    expect("LINUX_FS Exit effect=14 commit_sequence=14 status=0 syscall=exit resumed_after_exit=false")
    expect("EFFECT_REGISTRY Quiescent workload=linux-runtime-fs live=0 pending_publications=0 credits=Free")
    expect("LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=14 openat=3 pread64=2 statx=1 newfstatat=1 pwrite64=1 readlinkat=1 close=3 write=1 exit=1 commit_gate=true publication_acks=14 registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true real_dma=false virtio_evidence=component_consistency same_boot=false identity_preserving=false")
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
