# Validate the retained Round 4 futex execution, recovery, and closure trace.
#
# This is intentionally independent of the Stage 6B.1 projection parser.  It
# accepts scheduler/loader noise, but every LINUX_FUTEX_CORE receipt is known,
# unique where required, and tied to the immutable effect that caused it.

function fail(message) {
    print "linux futex core assertion failed at serial line " NR ": " message > "/dev/stderr"
    failed = 1
    exit 1
}

function field(name,    i, prefix) {
    prefix = name "="
    for (i = 3; i <= NF; i++) {
        if (index($i, prefix) == 1)
            return substr($i, length(prefix) + 1)
    }
    fail("missing field " name " in: " $0)
}

function exact_fields(expected, event) {
    if (NF != expected)
        fail(event " has " NF " fields; expected " expected)
}

function require(condition, message) {
    if (!condition)
        fail(message)
}

BEGIN {
    close_commit = "LINUX_FUTEX_CORE_CLOSE PASS case=commit-before-close affected=2 moved=1 drains=2 aborts=1 publications=3 move_preserved=true final_queues=0 final_indexes=0 final_credits=0"
    close_race = "LINUX_FUTEX_CORE_CLOSE PASS case=close-before-commit commit_result=StaleAuthority moved=0 drains=0 aborts=3 publications=3 failure_atomic=true final_queues=0 final_indexes=0 final_credits=0"
    final_line = "LINUX_FUTEX_CORE Final scope=Revoked queues=0 resource_indexes=0 effects=0 credits_held=0 credits_committed=0 threads=0 publications_fixed=1 stdout_publications=1"
    pass_line = "LINUX_FUTEX_CORE PASS workload=linux-round4-futex-smoke stdout_exact=true mmap_pages=8 clones=3 waits=4 wakes=2 requeues=1 affected_count=2 fifo=true atomic_move=true crash_rebind=true explicit_adoptions=3 stale_old_rejected=true fixed_receipt_publications=1 close_companions=2 final_empty=true single_cpu=true"
    clone_stack[1001] = "0x10002000"
    clone_stack[1002] = "0x10004000"
    clone_stack[1003] = "0x10006000"
}

{
    sub(/\r$/, "")

    if ($0 ~ /^LINUX_FUTEX_CORE_CLOSE /) {
        close_count++
        if (close_count == 1 && $0 != close_commit)
            fail("commit-before-close receipt mismatch")
        if (close_count == 2 && $0 != close_race)
            fail("close-before-commit receipt mismatch")
        if (close_count > 2)
            fail("unexpected additional close companion receipt")
        if (begin_count)
            fail("close companion ran after retained ELF began")
        next
    }

    if ($0 ~ /^LINUX_FUTEX_CORE_PERSONALITY_V1 /) {
        exact_fields(6, "personality v1 exit")
        require($2 == "EXIT", "unknown personality v1 receipt")
        require(field("task") == "700", "v1 exit task mismatch")
        require(field("reason") == "real_user_page_fault", "v1 did not exit by real page fault")
        require(field("committed_move") == "true" && field("publication") == "false",
                "v1 fault boundary did not retain an unpublished committed move")
        require(crash_count == 1 && v1_exit_count == 0, "v1 exit did not follow exactly one crash")
        v1_exit_count++
        next
    }

    if ($0 ~ /^LINUX_FUTEX_CORE_PERSONALITY_V2 /) {
        exact_fields(4, "personality v2 exit")
        require($2 == "EXIT" && field("task") == "701" && field("reason") == "protocol_complete",
                "fresh personality did not finish the protocol")
        require(final_count == 1 && v2_exit_count == 0, "v2 exited before the final quiescent receipt")
        v2_exit_count++
        next
    }

    if ($0 !~ /^LINUX_FUTEX_CORE /)
        next

    event = $2
    event_count[event]++

    if (event == "BEGIN") {
        exact_fields(11, event)
        require(close_count == 2, "retained ELF began before both close companions passed")
        require(field("workload") == "linux-round4-futex-smoke" && field("adapted") == "true",
                "wrong retained workload")
        require(field("elf") == "ET_EXEC" && field("entry") == "0x401000" && field("segments") == "4",
                "pinned Round 4 ELF identity mismatch")
        require(field("vm") == "Arc<VmSpace>" && field("single_cpu") == "true" &&
                field("private_futex") == "true",
                "bounded execution boundary mismatch")
        require(field("bounded_abi") == "mmap+clone+exit+exit_group+write+wait+wake+requeue",
                "bounded syscall surface mismatch")
        require(begin_count == 0, "duplicate BEGIN")
        begin_count++
        next
    }

    require(begin_count == 1, event " appeared outside the retained ELF interval")

    if (event == "Mmap") {
        exact_fields(9, event)
        require(field("task") == "1000" && field("address") == "0x10000000" &&
                field("pages") == "8" && field("length") == "32768" &&
                field("shared_vm") == "true" && field("anonymous") == "true" &&
                field("result") == "0x10000000", "mmap receipt mismatch")
        require(mmap_count == 0, "duplicate mmap")
        mmap_count++
        next
    }

    if (event == "WaitMismatch") {
        exact_fields(8, event)
        require(mmap_count == 1 && clone_count == 0, "WAIT mismatch occurred at the wrong point")
        require(field("task") == "1000" && field("key") == "0x403010" &&
                field("observed") == "1" && field("expected") == "0" &&
                field("result") == "-EAGAIN" && field("effect_created") == "false",
                "WAIT mismatch did not return -EAGAIN without an effect")
        require(mismatch_count == 0, "duplicate WAIT mismatch")
        mismatch_count++
        next
    }

    if (event == "Clone") {
        exact_fields(7, event)
        child = field("child") + 0
        require(field("parent") == "1000" && child == 1001 + clone_count,
                "clone TID order mismatch")
        require(field("child_stack") == clone_stack[child] &&
                field("shared_arc_vm") == "true" && field("flags") == "0x10f00",
                "clone did not retain the shared VmSpace contract")
        require(!(child in cloned), "duplicate clone TID")
        cloned[child] = 1
        clone_count++
        next
    }

    if (event == "WaitQueued") {
        exact_fields(9, event)
        task = field("task") + 0
        effect = field("effect") + 0
        position = field("fifo_position") + 0
        require(task in cloned, "waiter task was not cloned")
        require(!(effect in live), "duplicate wait effect")
        require(field("key") == "0x403010" && (position == 1 || position == 2) &&
                field("binding_epoch") == "1" && field("credit") == "Held" &&
                field("descriptor_args") == "6", "queued WAIT receipt mismatch")
        live[effect] = "wait"
        wait_task[effect] = task
        task_wait[task] = effect
        wait_position[effect] = position
        position_count[position]++
        wait_count++
        next
    }

    if (event == "Capture") {
        exact_fields(8, event)
        effect = field("effect") + 0
        operation = field("op")
        binding = field("binding_epoch") + 0
        require(field("task") == "1000" && !(effect in live), "invalid control caller/effect")
        require((operation == "WAKE" || operation == "REQUEUE") &&
                (binding == 1 || binding == 2) && field("immutable_descriptor") == "true" &&
                field("descriptor_args") == "6", "control capture mismatch")
        live[effect] = "control"
        control_op[effect] = operation
        control_binding[effect] = binding
        operation_count[operation]++
        capture_count++
        next
    }

    if (event == "GuestBlock") {
        exact_fields(5, event)
        task = field("task") + 0
        effect = field("effect") + 0
        require(effect in live && !(effect in blocked), "unknown or duplicate blocked effect")
        require(field("continuation") == "EffectWaiter", "blocked syscall lost its continuation")
        if (live[effect] == "wait")
            require(wait_task[effect] == task, "wait continuation task mismatch")
        else
            require(task == 1000, "control continuation task mismatch")
        blocked[effect] = 1
        block_count++
        next
    }

    if (event == "Prepare") {
        exact_fields(7, event)
        effect = field("effect") + 0
        personality = field("personality") + 0
        binding = field("binding_epoch") + 0
        require(live[effect] == "control" && blocked[effect] && !(effect in prepared),
                "prepare did not name one blocked control")
        require(binding == control_binding[effect] &&
                personality == (binding == 1 ? 700 : 701) &&
                field("opaque_handle") == "true" && field("descriptor_args") == "6",
                "prepare authority/descriptor mismatch")
        prepared[effect] = 1
        prepare_count++
        next
    }

    if (event == "Commit") {
        exact_fields(13, event)
        effect = field("effect") + 0
        operation = field("op")
        personality = field("personality") + 0
        revision = field("revision") + 0
        require(prepared[effect] && !(effect in committed), "commit did not name one prepared control")
        require(operation == control_op[effect] && revision == commit_count + 1 &&
                field("fifo") == "true" && field("atomic") == "true",
                "commit order/atomicity mismatch")

        if (revision == 1) {
            require(personality == 700 && operation == "WAKE" && field("woken") == "1" &&
                    field("moved") == "0" && field("affected") == "1" &&
                    field("moved_identity") == "0" && field("moved_credit") == "None",
                    "first WAKE commit mismatch")
        } else if (revision == 2) {
            require(personality == 700 && operation == "REQUEUE" && field("woken") == "1" &&
                    field("moved") == "1" && field("affected") == "2" &&
                    field("moved_credit") == "Held", "A-to-B requeue commit mismatch")
            moved_effect = field("moved_identity") + 0
            require(live[moved_effect] == "wait" && wait_position[moved_effect] == 2,
                    "requeue did not preserve and move the second FIFO waiter")
            requeue_control = effect
        } else if (revision == 3) {
            require(personality == 701 && operation == "WAKE" && field("woken") == "1" &&
                    field("moved") == "0" && field("affected") == "1" &&
                    field("moved_identity") == "0" && field("moved_credit") == "None",
                    "post-recovery WAKE commit mismatch")
        } else {
            fail("unexpected domain revision " revision)
        }

        committed[effect] = 1
        commit_result[effect] = field("affected") + 0
        current_commit = effect
        current_revision = revision
        commit_count++
        next
    }

    if (event == "Crash") {
        exact_fields(12, event)
        effect = field("effect") + 0
        require(commit_count == 2 && effect == requeue_control && crash_count == 0,
                "crash did not freeze the committed requeue")
        require(field("personality") == "700" && field("previous_binding_epoch") == "1" &&
                field("binding_epoch") == "2" && field("cohort") == "3" &&
                field("committed") == "true" && field("affected") == "2" &&
                field("moved_effect") + 0 == moved_effect &&
                field("queue_move_retained") == "true" && field("receipt_frozen") == "true",
                "crash receipt mismatch")
        live_at_crash = 0
        for (candidate in live)
            if (!(candidate in published)) live_at_crash++
        require(live_at_crash == 3, "crash cohort/domain live-set mismatch")
        crash_count++
        next
    }

    if (event == "FreshSpawn") {
        exact_fields(7, event)
        require(v1_exit_count == 1 && crash_count == 1 && fresh_count == 0,
                "replacement was not a fresh post-crash task")
        require(field("replacement") == "701" && field("vm") == "fresh" &&
                field("task") == "fresh" && field("binding_epoch") == "2" &&
                field("normal_handoff") == "true", "replacement receipt mismatch")
        fresh_count++
        next
    }

    if (event == "RecoveryTaskEntry") {
        exact_fields(4, event)
        phase = field("phase")
        require(fresh_count == 1 && recovery_stage == 0,
                "recovery task entry appeared outside the fresh replacement interval")
        require(field("replacement") == "701", "recovery task identity mismatch")
        if (phase == "kernel") {
            require(progress_stage == 0, "duplicate/out-of-order kernel task entry")
            progress_stage = 1
        } else if (phase == "vm_active") {
            require(progress_stage == 1, "VmSpace activation did not follow kernel task entry")
            progress_stage = 2
        } else {
            fail("unknown recovery task entry phase: " phase)
        }
        next
    }

    if (event == "RecoverySnapshotBegin") {
        exact_fields(3, event)
        require(field("replacement") == "701" && progress_stage == 2 && recovery_stage == 0,
                "snapshot begin did not follow active replacement VmSpace")
        progress_stage = 3
        next
    }

    if (event == "RecoveryRuntimeSectionComplete") {
        exact_fields(5, event)
        require(field("replacement") == "701" && field("lock_released") == "true" &&
                field("snapshot_captured") == "true" && progress_stage == 3 && recovery_stage == 0,
                "completed runtime snapshot section did not follow snapshot begin")
        progress_stage = 4
        next
    }

    if (event == "RecoverySnapshot") {
        exact_fields(9, event)
        require(fresh_count == 1 && progress_stage == 4 && recovery_stage == 0,
                "snapshot recovery order mismatch")
        require(field("replacement") == "701" && field("binding_epoch") == "2" &&
                field("effects") == "3" && field("committed_controls") == "1" &&
                field("queued_waits") == "1" && field("claimed_waits") == "1" &&
                field("exact") == "true", "recovery snapshot mismatch")
        recovery_stage = 1
        next
    }

    if (event == "Ready") {
        exact_fields(5, event)
        require(recovery_stage == 1 && field("replacement") == "701" &&
                field("binding_epoch") == "2" && field("snapshot_exact") == "true",
                "Ready gate mismatch")
        recovery_stage = 2
        next
    }

    if (event == "Rebind") {
        exact_fields(5, event)
        require(recovery_stage == 2 && field("replacement") == "701" &&
                field("binding_epoch") == "2" && field("fallback") == "false",
                "Rebind gate mismatch")
        recovery_stage = 3
        next
    }

    if (event == "Adopt") {
        exact_fields(9, event)
        effect = field("effect") + 0
        phase = field("phase")
        require(recovery_stage == 3 && effect in live && !(effect in adopted),
                "replacement adopted an effect outside the current crash cohort")
        require(field("replacement") == "701" && field("old_binding_epoch") == "1" &&
                field("binding_epoch") == "2" && field("explicit") == "true" &&
                field("descriptor_args") == "6", "adoption identity mismatch")
        require((effect == moved_effect && phase == "Prepared") ||
                (effect != moved_effect && phase == "Committed"),
                "adopted phase does not match frozen cohort role")
        adopted[effect] = 1
        adopted_phase[phase]++
        adopt_count++
        next
    }

    if (event == "LateOldGeneration") {
        exact_fields(8, event)
        require(recovery_stage == 3 && adopt_count == 3 && late_count == 0,
                "old binding was tested before explicit cohort adoption completed")
        require(field("sender") == "700" && field("old_binding_epoch") == "1" &&
                field("current_binding_epoch") == "2" && field("result") == "StaleBinding" &&
                field("mutation") == "false" &&
                field("projection") == "scope+effects+current_resources+domain_queues",
                "late v1 call was not a full-projection no-op")
        late_count++
        next
    }

    if (event == "Publish") {
        exact_fields(9, event)
        effect = field("effect") + 0
        kind = field("kind")
        result = field("result") + 0
        frozen = field("frozen")
        personality = field("personality") + 0
        require(effect in live && !(effect in published), "unknown or duplicate publication")
        require(field("one_shot") == "true" && field("ack") == "true",
                "publication was not one-shot and acknowledged")
        require((kind == "wait" && live[effect] == "wait") ||
                (kind == "control" && live[effect] == "control"),
                "publication kind/effect mismatch")
        if (kind == "wait")
            require(result == 0, "wait publication result mismatch")
        else
            require(committed[effect] && result == commit_result[effect],
                    "control publication result does not match its commit receipt")

        if (frozen == "true") {
            require(personality == 701 && current_revision == 2 && late_count == 1,
                    "frozen receipt was not published by the replacement after stale rejection")
            require((kind == "control" && effect == requeue_control) ||
                    (kind == "wait" && effect != moved_effect && wait_position[effect] == 1),
                    "frozen receipt selected the wrong FIFO effect")
            frozen_publications++
        } else if (frozen == "false") {
            require((current_revision == 1 && personality == 700) ||
                    (current_revision == 3 && personality == 701),
                    "normal publication used the wrong service generation")
            if (kind == "wait" && current_revision == 3)
                require(effect == moved_effect, "post-recovery WAKE did not target the requeued waiter")
            normal_publications++
        } else {
            fail("malformed frozen publication flag")
        }
        published[effect] = 1
        publication_result[effect] = result
        delete live[effect]
        publication_count++
        next
    }

    if (event == "FrozenReceipt") {
        exact_fields(5, event)
        require(frozen_publications == 2 && frozen_receipt_count == 0,
                "frozen receipt did not publish exactly one wait/control pair")
        require(field("publication") == "1" && field("affected_count") == "2" &&
                field("duplicate") == "false", "frozen receipt summary mismatch")
        frozen_receipt_count++
        next
    }

    if (event == "GuestResume") {
        exact_fields(6, event)
        task = field("task") + 0
        effect = field("effect") + 0
        require(effect in published && !(effect in resumed), "resume lacks one prior publication")
        require(field("linux_result") + 0 == publication_result[effect] &&
                field("one_shot") == "true", "guest resume result mismatch")
        if (effect in wait_task)
            require(task == wait_task[effect], "wait resumed the wrong task")
        else
            require(task == 1000, "control resumed the wrong task")
        resumed[effect] = 1
        resume_count++
        next
    }

    if (event == "ThreadExit") {
        exact_fields(5, event)
        task = field("task") + 0
        require(task in cloned && !(task in exited), "unknown or duplicate child exit")
        require(task_wait[task] in resumed && field("status") == "0",
                "child exited before its futex continuation resumed")
        remaining = field("remaining_threads") + 0
        require(remaining >= 1 && remaining <= 2, "child exit retained an invalid thread count")
        exited[task] = 1
        exit_count++
        next
    }

    if (event == "stdout=round4") {
        require($0 == "LINUX_FUTEX_CORE stdout=round4 futex ok", "stdout receipt mismatch")
        require(exit_count == 3 && stdout_count == 0, "stdout published before all children exited")
        stdout_count++
        next
    }

    if (event == "ExitGroup") {
        exact_fields(6, event)
        require(stdout_count == 1 && exit_count == 3 && exit_group_count == 0,
                "exit_group order mismatch")
        require(field("task") == "1000" && field("status") == "0" &&
                field("remaining_threads") == "0" && field("shutdown_queued") == "true",
                "exit_group receipt mismatch")
        exit_group_count++
        next
    }

    if (event == "Final") {
        require($0 == final_line, "final quiescent projection mismatch")
        require(exit_group_count == 1 && length(live) == 0 && final_count == 0,
                "final projection preceded complete queue/effect shutdown")
        final_count++
        next
    }

    if (event == "PASS") {
        require($0 == pass_line, "terminal PASS receipt mismatch")
        require(final_count == 1 && v2_exit_count == 1 && pass_count == 0,
                "PASS did not follow fresh-service completion and quiescence")
        pass_count++
        next
    }

    fail("unknown retained Round 4 receipt: " $0)
}

END {
    if (failed)
        exit 1
    require(close_count == 2, "expected two close companion receipts")
    require(begin_count == 1 && pass_count == 1, "missing unique BEGIN/PASS boundary")
    require(mmap_count == 1 && mismatch_count == 1, "mmap/WAIT mismatch count mismatch")
    require(clone_count == 3 && wait_count == 3 && capture_count == 3,
            "clone/wait/control count mismatch")
    require(position_count[1] == 2 && position_count[2] == 1,
            "FIFO queue positions mismatch")
    require(operation_count["WAKE"] == 2 && operation_count["REQUEUE"] == 1,
            "WAKE/REQUEUE operation count mismatch")
    require(block_count == 6 && prepare_count == 3 && commit_count == 3,
            "block/prepare/commit count mismatch")
    require(crash_count == 1 && v1_exit_count == 1 && fresh_count == 1,
            "crash/fresh replacement count mismatch")
    require(progress_stage == 4, "replacement progress instrumentation did not reach the runtime")
    require(recovery_stage == 3 && adopt_count == 3 &&
            adopted_phase["Committed"] == 2 && adopted_phase["Prepared"] == 1,
            "explicit recovery cohort mismatch")
    require(late_count == 1 && frozen_receipt_count == 1,
            "stale old-binding/frozen receipt count mismatch")
    require(publication_count == 6 && frozen_publications == 2 && normal_publications == 4,
            "publication count mismatch")
    require(resume_count == 6 && exit_count == 3 && stdout_count == 1 && exit_group_count == 1,
            "guest continuation/lifecycle count mismatch")
    require(final_count == 1 && v2_exit_count == 1,
            "fresh service did not reach one quiescent terminal state")
}
