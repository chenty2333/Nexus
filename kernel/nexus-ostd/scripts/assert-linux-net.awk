# Validate the exact unchanged Stage 6 runtime-network execution and its
# bounded netd/readiness recovery lifecycle. Scheduler and other workload noise
# is ignored; every network-relevant receipt must occur exactly once and in
# order, and no line may escalate the deliberately narrow transport claims.

function fail(message) {
    print "runtime network assertion failed at serial line " NR ": " message > "/dev/stderr"
    failed = 1
    exit 1
}

function expect(line) {
    expected[++expected_count] = line
}

BEGIN {
    expect("NETWORK_LIFECYCLE BEGIN authority_epoch=241 personality_binding=1 netd_binding=1 readiness_binding=1 socket_generation=1 source_generation=1 bounded=true single_cpu=true")
    expect("LINUX_NET_SLICE BEGIN workload=linux-runtime-net-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=22 unique_syscalls=13 registry=common transport=bounded_in_memory_ipv4_loopback readiness=kernel_owned smp=1")
    expect("LINUX_NET_ARTIFACT source_sha256=65ba020b526fe1cbf05feef0739791a3ae6274b2ffa2b39d385ce88e1a086ecf elf_sha256=8cdd5864c07e51e91d9e0a6ec94e4d7d6438db2fbb39d513bfb7c5624d32f549 retained=true smoltcp=false virtio_net=false external_packets=false tcp_breadth=false")
    expect("LINUX_NET Socket syscall=1 effect=1 commit_sequence=1 fd=3 domain=AF_INET type=SOCK_STREAM protocol=0 role=listener")
    expect("LINUX_NET SetSockOpt syscall=2 effect=2 commit_sequence=2 fd=3 option=SO_REUSEADDR value=1 len=4 accepted=true")
    expect("LINUX_NET Bind syscall=3 effect=3 commit_sequence=3 fd=3 address=127.0.0.1 port=4242 sockaddr_len=16")
    expect("LINUX_NET GetSockName syscall=4 effect=4 commit_sequence=4 fd=3 endpoint=listener family=AF_INET address=127.0.0.1 port=4242 sockaddr_len=16")
    expect("LINUX_NET Listen syscall=5 effect=5 commit_sequence=5 fd=3 backlog=4")
    expect("LINUX_NET Socket syscall=6 effect=6 commit_sequence=6 fd=4 domain=AF_INET type=SOCK_STREAM protocol=0 role=client")
    expect("LINUX_NET SetSockOpt syscall=7 effect=7 commit_sequence=7 fd=4 option=TCP_NODELAY value=1 len=4 accepted=true")
    expect("LINUX_NET Connect syscall=8 effect=8 commit_sequence=8 fd=4 peer=127.0.0.1:4242 local_port=49153 pending_accept=true ready_source=1 ready_mask=READABLE")
    expect("LINUX_NET GetPeerName syscall=9 effect=9 commit_sequence=9 fd=4 peer=127.0.0.1:4242 sockaddr_len=16")
    expect("NETWORK_LIFECYCLE NetdCrash syscall=10 old_binding=1 new_binding=2 cohort=2 prepared_accept=true prepared_readiness=true peer_epochs_unchanged=true real_user_page_fault=true")
    expect("NETD_V1 EXIT task=1051 reason=real_user_page_fault addr=0x800000 accept_prepared=true accept_committed=false guest_reply=false")
    expect("NETWORK_LIFECYCLE FreshSpawn task=1052 vm=fresh distinct_task=true distinct_vm=true binding=2")
    expect("NETWORK_LIFECYCLE Snapshot replacement=1052 binding=2 cohort=2 exact=true")
    expect("NETWORK_LIFECYCLE Ready replacement=1052 binding=2 snapshot_fresh=true")
    expect("NETWORK_LIFECYCLE Rebind replacement=1052 binding=2 personality_binding=1 readiness_binding=1 peer_epochs_unchanged=true")
    expect("NETWORK_LIFECYCLE Adopt replacement=1052 effect=10 kind=accept old_binding=1 new_binding=2 explicit=true")
    expect("NETWORK_LIFECYCLE Adopt replacement=1052 effect=11 kind=readiness old_binding=1 new_binding=2 explicit=true")
    expect("NETWORK_LIFECYCLE StaleReplay sender=1051 old_binding=1 current_binding=2 result=StaleBinding projection_before=91f9d355b6291f83 projection_after=91f9d355b6291f83 full_projection_unchanged=true mutation=false")
    expect("LINUX_NET Accept syscall=10 effect=10 commit_sequence=10 fd=5 listener=3 peer=127.0.0.1:49153 flags=0 readiness_effect=11 delivery_sequence=1 recovered_by_v2=true")
    expect("LINUX_NET GetSockName syscall=11 effect=12 commit_sequence=12 fd=4 endpoint=client_local family=AF_INET address=127.0.0.1 port=49153 sockaddr_len=16")
    expect("LINUX_NET Write syscall=12 effect=13 commit_sequence=13 direction=client_to_accepted bytes=4 payload=ping buffer_effect=14 buffer_credit=Held")
    expect("LINUX_NET Read syscall=13 effect=15 commit_sequence=14 direction=client_to_accepted bytes=4 payload=ping buffer_effect=14 buffer_credit=Returned")
    expect("LINUX_NET Write syscall=14 effect=16 commit_sequence=16 direction=accepted_to_client bytes=4 payload=pong buffer_effect=17 buffer_credit=Held")
    expect("LINUX_NET Read syscall=15 effect=18 commit_sequence=17 direction=accepted_to_client bytes=4 payload=pong buffer_effect=17 buffer_credit=Returned")
    expect("LINUX_NET Shutdown syscall=16 effect=19 commit_sequence=19 fd=4 how=SHUT_WR peer_hangup=true")
    expect("LINUX_NET Read syscall=17 effect=20 commit_sequence=20 direction=accepted_from_client bytes=0 eof=true")
    expect("LINUX_NET Close syscall=18 effect=21 commit_sequence=21 fd=5 role=accepted remaining_runtime_fds=2")
    expect("LINUX_NET Close syscall=19 effect=22 commit_sequence=22 fd=4 role=client remaining_runtime_fds=1")
    expect("LINUX_NET Close syscall=20 effect=23 commit_sequence=23 fd=3 role=listener remaining_runtime_fds=0")
    expect("LINUX_NET Write syscall=21 effect=24 commit_sequence=24 fd=1 bytes=15 stdout_exact=true")
    expect("LINUX_NET stdout=runtime net ok")
    expect("LINUX_NET Exit syscall=22 effect=25 commit_sequence=25 status=0 syscall=exit resumed_after_exit=false")
    expect("EFFECT_REGISTRY Quiescent workload=linux-runtime-net live=0 pending_publications=0 credits=Free resources=empty")
    expect("LINUX_NET_SLICE PASS workload=linux-runtime-net-smoke retained=true adapted=false syscalls=22 unique_syscalls=13 network_ops=20 netd_v1_calls=10 netd_v2_calls=10 real_user_mode_netd=true real_v1_page_fault=true snapshot_ready_rebind_adopt=true ping_pong=true shutdown_eof=true commit_gate=true publication_acks=22 readiness=kernel_owned buffer_credit=consume_or_closure registry_quiescent=true runtime_network=true bounded_loopback=true single_cpu=true smoltcp=false virtio_net=false external_packets=false tcp_breadth=false")
    expect("NETD_V2 EXIT task=1052 reason=bounded_service_done recovered_accept=true remaining_ops=10")
    expect("NETWORK_COMPANION READY_REVOKE Transition case=ready-first scope=106 step=ReadyCommit commit_sequence=3 ready_publications=1")
    expect("NETWORK_COMPANION READY_REVOKE Transition case=ready-first scope=106 step=RevokeBegin authority_epoch=301->302 closure_sequence=1")
    expect("NETWORK_COMPANION READY_REVOKE PASS case=ready-first scope=106 winner=ReadyCommit order=ready_commit_before_revoke net_publications=1 ready_publications=1 ready_deliveries=1 wait_final=Completed guest_commits=0 guest_replies=0 buffer_disposition=ClosureDrain credits=Free quiescent=true bounded=true single_cpu=true")
    expect("NETWORK_COMPANION READY_REVOKE Transition case=revoke-first scope=107 step=RevokeBegin authority_epoch=301->302 closure_sequence=1")
    expect("NETWORK_COMPANION READY_REVOKE Transition case=revoke-first scope=107 step=ReadyCommitReject result=StaleAuthority full_projection_unchanged=true mutation=false")
    expect("NETWORK_COMPANION READY_REVOKE PASS case=revoke-first scope=107 winner=RevokeBegin order=revoke_before_ready ready_commit_result=StaleAuthority net_publications=1 ready_publications=0 ready_deliveries=0 wait_final=Aborted guest_commits=0 guest_replies=0 buffer_disposition=ClosureDrain credits=Free quiescent=true bounded=true single_cpu=true")
    expect("NETWORK_COMPANION PERSONALITY_CRASH PASS scope=108 old_binding=1 new_binding=2 send_phase_at_crash=Committed send_disposition=Drain send_replies=1 receive_phase_at_crash=Prepared receive_disposition=Abort receive_replies=0 committed_adoptions=0 terminalizations=2 credits=Free quiescent=true bounded=true single_cpu=true")
    expect("NETWORK_COMPANION BUFFER_REPLY PASS scope=109 net_sequence=1 buffer_effect=4 payload=ping bytes=4 visible_before=1 buffer_credit_before=Held guest_commits_before=0 guest_replies_before=0 peer_consumptions=0 closure_drains=1 visible_after=0 buffer_credit_after=Free net_publications_after=1 guest_replies_after=0 immutable_history=true quiescent=true bounded=true single_cpu=true")
    expect("NETWORK_COMPANION STALE_GENERATION PASS kind=socket scope=110 effect=2 presented=1 current=2 result=StaleSocketGeneration projection_before=226d72df438c378a projection_after=226d72df438c378a full_projection_unchanged=true mutation=false bounded=true single_cpu=true")
    expect("NETWORK_COMPANION STALE_GENERATION PASS kind=source scope=111 effect=3 presented=1 current=2 result=StaleSourceGeneration projection_before=d6aaade85b9606e9 projection_after=d6aaade85b9606e9 full_projection_unchanged=true mutation=false bounded=true single_cpu=true")
    expect("NETWORK_LIFECYCLE PASS netd_crash_adopt_accept=true stale_old_binding_full_projection_unchanged=true ready_commit_first=true ready_revoke_first=true personality_crash_drain_abort=true buffer_visible_reply_absent=true stale_socket_generation_full_projection_unchanged=true stale_source_generation_full_projection_unchanged=true stale_authority_full_projection_unchanged=true companion_quiescent=true netd_crash_peer_epochs_unchanged=true binding_isolation_observed=netd_crash_only socket_generation_fenced=true source_generation_fenced=true kernel_owned_readiness=true buffer_credit_retained_until_consume=true quiescent=true bounded=true single_cpu=true smoltcp=false virtio_net=false external_packets=false")
}

{
    sub(/\r$/, "")

    if ($0 ~ /(^| )(smoltcp|virtio_net|external_packets|tcp_breadth)=true( |$)/)
        fail("unestablished network capability was escalated: " $0)
    if ($0 ~ /^(NETWORK_LIFECYCLE|NETWORK_COMPANION|NETD_V[12]|LINUX_NET( |_))/ &&
        $0 ~ /(^| )(bounded_loopback|single_cpu)=false( |$)/)
        fail("bounded single-CPU network boundary was weakened: " $0)

    relevant = ($0 ~ /^NETWORK_LIFECYCLE / ||
                $0 ~ /^NETWORK_COMPANION / ||
                $0 ~ /^NETD_V[12] / ||
                $0 ~ /^LINUX_NET( |_)/ ||
                $0 ~ /^EFFECT_REGISTRY Quiescent workload=linux-runtime-net /)
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
    if (NR == 0)
        exit 0
    if (observed != expected_count)
        fail("expected " expected_count " receipts, observed " (observed + 0))
}
