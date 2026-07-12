#!/usr/bin/awk -f

# Strict serial oracle for the bounded dynamic-PIE exec/recovery slice.
#
# This intentionally accepts one trace shape.  It checks the real launcher
# execve capture, eight PT_LOAD plus TLS/stack receipts, v1 crash, snapshot/ready/rebind,
# per-effect adoption, failure-atomic stale-handle probes, the single atomic
# ExecCommit and VmSpace publication, exact guest stdout, write/exit
# publication acknowledgements, and final registry closure.

function fail(message) {
    print "dynamic PIE serial assertion failed: " message > "/dev/stderr"
    failed = 1
    exit 1
}

function mark(name) {
    if (seen[name]++) {
        fail("duplicate marker " name " at line " NR)
    }
    ordinal = order[name]
    if (ordinal == 0) {
        fail("unknown marker " name " at line " NR)
    }
    if (ordinal != last_ordinal + 1) {
        fail("out-of-order marker " name " at line " NR "; expected ordinal " \
             (last_ordinal + 1) ", observed " ordinal)
    }
    last_ordinal = ordinal
}

BEGIN {
    order["begin"] = 1
    order["execve"] = 2
    order["stage"] = 3
    order["v1_observe"] = 4
    order["crash"] = 5
    order["fresh_spawn"] = 6
    order["snapshot"] = 7
    order["ready"] = 8
    order["rebind"] = 9
    for (order_index = 1; order_index <= 11; order_index++)
        order["adopt" order_index] = 9 + order_index
    order["stale_precommit"] = 21
    order["exec_commit"] = 22
    order["vm_publish"] = 23
    order["exec_ack"] = 24
    order["stale_postcommit"] = 25
    order["v2_exit"] = 26
    order["old_image"] = 27
    order["resume"] = 28
    order["stdout"] = 29
    order["write_ack"] = 30
    order["exit_ack"] = 31
    order["quiescent"] = 32
    order["pass"] = 33
    order["spike_pass"] = 34
}

{
    sub(/\r$/, "")
}

$0 == "LINUX_DYNAMIC_SLICE BEGIN workload=linux-dynamic-pie launcher=ET_EXEC exec_target=ET_DYN interpreter=ET_DYN registry=common smp=1 tls_tasks=1" {
    mark("begin")
    next
}

$0 == "LINUX_DYNAMIC ExecveCapture task=800 nr=59 path=/bin/linux-dynamic-pie-main argv0=exact envp=null real_user_syscall=true" {
    mark("execve")
    next
}

$0 == "LINUX_DYNAMIC Stage main_segments=4 interpreter_segments=4 tls_modules=2 tls_effects=1 stack=initial stack_effects=1 registry_effects=11 credits_held=11 committed=false" {
    mark("stage")
    next
}

$0 == "LINUX_DYNAMIC_PERSONALITY_V1 Observe task=801 staging=complete exec_committed=false result=Applied" {
    mark("v1_observe")
    next
}

$0 == "LINUX_DYNAMIC_PERSONALITY Crash task=801 binding_before=1 binding_after=2 cohort=11 staging_recoverable=true" {
    mark("crash")
    next
}

$0 == "LINUX_DYNAMIC_RECOVERY FreshSpawn task=802 vm=fresh binding=2 fs_base=explicit-zero" {
    mark("fresh_spawn")
    next
}

$0 == "LINUX_DYNAMIC_RECOVERY Snapshot replacement=802 binding=2 revision=23 effects=11 immutable=true" {
    mark("snapshot")
    next
}

$0 == "LINUX_DYNAMIC_RECOVERY Ready replacement=802 snapshot_binding=2 result=Applied" {
    mark("ready")
    next
}

$0 == "LINUX_DYNAMIC_RECOVERY Rebind replacement=802 binding=2 result=Applied" {
    mark("rebind")
    next
}

$0 ~ /^LINUX_DYNAMIC_RECOVERY Adopt index=(10|11|[1-9]) effect=(10|11|[1-9]) kind=(exec|segment|tls|stack) old_binding=1 new_binding=2 explicit=true$/ {
    split($3, index_field, "=")
    split($4, effect_field, "=")
    split($5, kind_field, "=")
    adoption_index = index_field[2] + 0
    effect = effect_field[2] + 0
    kind = kind_field[2]
    if (adoption_index != adopt_count + 1 || effect != adoption_index) {
        fail("adoption identity/order mismatch at line " NR)
    }
    if ((adoption_index == 1 && kind != "exec") ||
        (adoption_index >= 2 && adoption_index <= 9 && kind != "segment") ||
        (adoption_index == 10 && kind != "tls") ||
        (adoption_index == 11 && kind != "stack")) {
        fail("adoption kind mismatch at line " NR)
    }
    mark("adopt" adoption_index)
    adopt_count++
    next
}

$0 == "LINUX_DYNAMIC OldHandleReject point=precommit result=StaleBinding state_unchanged=true registry_projection_unchanged=true image_projection_unchanged=true count=1" {
    if (adopt_count != 11) {
        fail("precommit stale probe occurred before eleven explicit adoptions")
    }
    mark("stale_precommit")
    next
}

$0 == "LINUX_DYNAMIC ExecCommit binding=2 effects=11 commit_count=1 atomic_batch=true pending_vm_publication=true" {
    mark("exec_commit")
    next
}

$0 == "LINUX_DYNAMIC VmSpacePublish generation_before=1 generation_after=2 interpreter_entry=0x2000012d0 main_entry=0x1000012e0 stack=0x7fffffffee00 fs_base=0x700000000014 outside_registry_lock=true" {
    mark("vm_publish")
    next
}

$0 == "LINUX_DYNAMIC ExecPublicationAck effect=1 pending_publications=0 staging_consumed=true old_image_recoverable=false" {
    mark("exec_ack")
    next
}

$0 == "LINUX_DYNAMIC OldHandleReject point=postcommit result=StaleBinding state_unchanged=true registry_projection_unchanged=true image_projection_unchanged=true count=2" {
    mark("stale_postcommit")
    next
}

$0 == "LINUX_DYNAMIC_RECOVERY V2Exit task=802 reason=return_to_zero completed=true" {
    mark("v2_exit")
    next
}

$0 == "LINUX_DYNAMIC OldImage generation=1 recoverable=false strong_refs=0 exec_commit_count=1" {
    mark("old_image")
    next
}

$0 == "LINUX_DYNAMIC Resume entry=interpreter rip=0x2000012d0 main_entry=0x1000012e0 stack=0x7fffffffee00 fs_base=0x700000000014 auxv_at_base=true auxv_at_entry=true" {
    mark("resume")
    next
}

$0 == "dynamic pie ok" {
    mark("stdout")
    stdout_count++
    next
}

$0 == "LINUX_DYNAMIC WritePublicationAck effect=12 bytes=15 stdout_exact=true ack_count=1" {
    mark("write_ack")
    next
}

$0 == "LINUX_DYNAMIC ExitPublicationAck effect=13 status=0 resumed=false ack_count=1" {
    mark("exit_ack")
    next
}

$0 == "EFFECT_REGISTRY Quiescent workload=linux-dynamic-pie live=0 pending_publications=0 credits_free=12 credits_capacity=12 scope=Revoked" {
    mark("quiescent")
    next
}

$0 == "LINUX_DYNAMIC_SLICE PASS workload=linux-dynamic-pie launcher_execve=true main_segments=4 interpreter_segments=4 tls=true tls_effects=1 stack_effects=1 auxv=true fsbase_explicit=true exec_commits=1 adoptions=11 stale_unchanged=2 stdout_exact=true publication_acks=3 registry_quiescent=true smp=1 tls_tasks=1" {
    mark("pass")
    next
}

$0 == "SPIKE_RESULT PASS" {
    if (seen["pass"]) {
        mark("spike_pass")
    }
    next
}

/^(LINUX_DYNAMIC|LINUX_DYNAMIC_PERSONALITY|LINUX_DYNAMIC_RECOVERY)/ {
    fail("unexpected dynamic trace line " NR ": " $0)
}

END {
    if (failed) {
        exit 1
    }
    required[1] = "begin"
    required[2] = "execve"
    required[3] = "stage"
    required[4] = "v1_observe"
    required[5] = "crash"
    required[6] = "fresh_spawn"
    required[7] = "snapshot"
    required[8] = "ready"
    required[9] = "rebind"
    required[10] = "stale_precommit"
    required[11] = "exec_commit"
    required[12] = "vm_publish"
    required[13] = "exec_ack"
    required[14] = "stale_postcommit"
    required[15] = "v2_exit"
    required[16] = "old_image"
    required[17] = "resume"
    required[18] = "stdout"
    required[19] = "write_ack"
    required[20] = "exit_ack"
    required[21] = "quiescent"
    required[22] = "pass"
    required[23] = "spike_pass"
    for (required_index = 1; required_index <= 23; required_index++) {
        if (seen[required[required_index]] != 1) {
            fail("missing marker " required[required_index])
        }
    }
    if (adopt_count != 11) {
        fail("expected 11 explicit adoptions, saw " adopt_count)
    }
    if (stdout_count != 1) {
        fail("expected exact stdout once, saw " stdout_count)
    }
    print "dynamic PIE serial assertions: PASS execve=real staging_effects=11 pt_load=8 tls=1 stack=1 adoptions=11 exec_commits=1 stale_unchanged=2 stdout_exact=1 publication_acks=3 quiescent=true"
}
