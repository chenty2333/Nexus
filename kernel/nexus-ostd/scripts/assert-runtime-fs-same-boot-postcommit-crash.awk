# SPDX-License-Identifier: MPL-2.0

function fail(message) {
    print "runtime filesystem same-boot postcommit assertion failed: " message > "/dev/stderr"
    failed = 1
    exit 1
}

function field(name,    prefix, i, found, value) {
    prefix = name "="
    found = 0
    for (i = 1; i <= NF; i++) {
        if (index($i, prefix) == 1) {
            found++
            value = substr($i, length(prefix) + 1)
        }
    }
    if (found != 1)
        fail("expected one " name " field: " $0)
    return value
}

function require_field(name, expected,    actual) {
    actual = field(name)
    if (actual != expected)
        fail("expected " name "=" expected ", observed " actual ": " $0)
    return actual
}

function require_decimal(value, label, allow_zero) {
    if ((allow_zero && value !~ /^(0|[1-9][0-9]*)$/) ||
        (!allow_zero && value !~ /^[1-9][0-9]*$/))
        fail("malformed decimal " label "=" value)
}

function require_hex(value, label) {
    if (value !~ /^0x[0-9a-f]+$/)
        fail("malformed lowercase hexadecimal " label "=" value)
}

function require_page_address(value, label) {
    if (value !~ /^0x[1-9a-f][0-9a-f]*000$/)
        fail("nonzero page-aligned address required for " label "=" value)
}

function require_device_event(name) {
    device_events++
    if (expected_device_event[device_events] != name)
        fail("device event " device_events " expected " \
             expected_device_event[device_events] ", observed " name)
}

function require_postcommit_event(name) {
    postcommit_events++
    if (expected_postcommit_event[postcommit_events] != name)
        fail("postcommit event " postcommit_events " expected " \
             expected_postcommit_event[postcommit_events] ", observed " name)
}

function add_effect(effect, label) {
    require_decimal(effect, label, 0)
    if (effect in effect_label)
        fail("duplicate effect identity " effect " for " label " and " effect_label[effect])
    effect_label[effect] = label
}

function require_postcommit_identity(cookie, ticket, request, root, label) {
    if (cookie != flight_cookie || ticket != ticket_effect ||
        request != causal_request || root != causal_root)
        fail(label " changed the pending flight/ticket/causal identity: " $0)
}

function parse_capture(    session) {
    require_device_event("Capture")
    if (NF != 18 || $3 != "same_boot=true" ||
        $4 != "identity_preserving=true" || $5 != "real_dma=true" ||
        $6 != "registry=shared_production" || $7 != "scope=95" ||
        $8 != "authority_epoch=141" || $9 != "effects=6" ||
        $10 != "credits=10" || $11 != "device=00:05.0" ||
        $13 != "generation=1" || $14 != "queue=0")
        fail("malformed Capture receipt: " $0)
    session = field("session")
    require_hex(session, "session")
    if (length(session) != 18)
        fail("device session is not a 64-bit identity: " session)
    descriptor = field("descriptor")
    require_decimal(descriptor, "descriptor", 1)
    syscall_effect = field("syscall_effect")
    filesystem_effect = field("filesystem_effect")
    block_effect = field("block_effect")
    add_effect(syscall_effect, "filesystem_syscall")
    add_effect(filesystem_effect, "filesystem_read")
    add_effect(block_effect, "block_request")
    capture_line = FNR
}

function parse_dma_owner(    kind, effect, paddr, iova, position) {
    require_device_event("DmaOwner")
    if (NF != 10 || $7 != "page_size=4096" || $8 != "queue=0" ||
        $10 != "generation=1" || field("descriptor") != descriptor)
        fail("malformed DmaOwner receipt: " $0)
    position = device_events - 1
    kind = field("kind")
    if (kind != expected_owner_kind[position])
        fail("unexpected DMA owner ordering: " $0)
    effect = field("effect")
    add_effect(effect, kind)
    paddr = field("paddr")
    iova = field("iova")
    require_page_address(paddr, kind "_paddr")
    require_page_address(iova, kind "_iova")
    if (paddr == iova || paddr in owner_kind_by_paddr ||
        paddr in owner_kind_by_iova || iova in owner_kind_by_paddr ||
        iova in owner_kind_by_iova)
        fail("DMA owner address is identity-mapped or duplicated: " $0)
    owner_effect[kind] = effect
    owner_paddr[kind] = paddr
    owner_iova[kind] = iova
    owner_kind_by_paddr[paddr] = kind
    owner_kind_by_iova[iova] = kind
    owners++
}

function parse_commit() {
    require_device_event("Commit")
    if (NF != 12 || $4 != "commit_point=avail_idx_release" ||
        $11 != "publication_once=true" || $12 != "revoke_begin_immediate=true" ||
        field("syscall_effect") != syscall_effect ||
        field("filesystem_effect") != filesystem_effect ||
        field("block_effect") != block_effect ||
        field("dma_queue_owner_a_effect") != owner_effect["queue_driver"] ||
        field("dma_queue_owner_b_effect") != owner_effect["queue_device"] ||
        field("dma_request_owner_effect") != owner_effect["request"])
        fail("Commit does not bind the exact captured cohort: " $0)
    require_decimal(field("batch_sequence"), "batch_sequence", 0)
    commit_line = FNR
}

function parse_postcommit(    event, before, after, cookie, ticket, request, root,
                              old_epoch, current_epoch) {
    event = $2
    require_postcommit_event(event)
    if (event == "BEGIN") {
        require_field("workload", "linux-runtime-fs-smoke")
        require_field("crash_boundary", "post_backend_pre_publication")
        require_field("backend", "virtio_blk")
        require_field("flight", "AwaitingPublication")
        require_field("v2_fault", "real_user_page_fault")
        require_field("v3", "closure_trigger_only")
        require_field("registry_replacement", "false")
        require_field("publication_actor", "original_guest")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        begin_line = FNR
    } else if (event == "Crash") {
        require_field("runner", "fsd-v2")
        require_field("task", "951")
        require_field("task_generation", "2")
        require_field("real_user_page_fault", "true")
        require_field("reason", "real_user_page_fault")
        if (field("addr") != "0x800000")
            fail("postcommit V2 fault address changed: " $0)
        require_field("backend_completion", "true")
        require_field("phase", "Closing")
        require_field("live_effects", "0")
        require_field("pending_publications", "1")
        require_field("flight", "AwaitingPublication")
        require_field("causal_state", "Active")
        require_field("outcome_present", "true")
        require_field("reply_wakeups", "0")
        require_field("guest_reply", "false")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        flight_cookie = field("flight_cookie")
        ticket_effect = field("ticket_effect")
        causal_request = field("causal_request")
        causal_root = field("causal_root")
        require_decimal(flight_cookie, "flight_cookie", 0)
        require_decimal(ticket_effect, "ticket_effect", 0)
        require_decimal(causal_request, "causal_request", 0)
        require_decimal(causal_root, "causal_root", 0)
        if (ticket_effect != causal_root)
            fail("publication ticket and causal root diverged: " $0)
        crash_line = FNR
    } else if (event == "FreshTrigger") {
        require_field("runner", "fsd-v3")
        require_field("task", "951")
        require_field("task_generation", "3")
        require_field("vm", "fresh")
        require_field("after_v2_waiter", "true")
        require_field("phase", "PostcommitCrashed")
        require_field("distinct_task", "true")
        require_field("distinct_vm", "true")
        require_field("closure_trigger_only", "true")
        require_field("registry_replacement", "false")
        require_field("registry_task", "false")
        require_field("causal_service_task_facade_observed", "false")
        require_field("causal_fault_matrix_promotion", "false")
        require_field("recommit", "false")
        require_field("rebind", "false")
        require_field("adopt", "false")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        fresh_trigger_line = FNR
    } else if (event == "StaleProbe") {
        require_field("trigger", "fsd-v3")
        require_field("trigger_task", "951")
        require_field("trigger_generation", "3")
        require_field("registry_replacement", "false")
        require_field("causal_service_task_facade_observed", "false")
        require_field("causal_fault_matrix_promotion", "false")
        require_field("presented_sender", "fsd-v2")
        require_field("presented_task", "951")
        require_field("presented_generation", "2")
        require_field("result", "StaleAuthority")
        require_field("registry_projection_unchanged", "true")
        require_field("flight_identity_unchanged", "true")
        require_field("causal_identity_unchanged", "true")
        require_field("causal_state", "Active")
        require_field("same_causal_session", "true")
        require_field("recommit", "false")
        require_field("rebind", "false")
        require_field("adopt", "false")
        require_decimal(field("effect"), "stale_effect", 0)
        old_epoch = field("old_authority_epoch")
        current_epoch = field("current_authority_epoch")
        require_decimal(old_epoch, "old_authority_epoch", 0)
        require_decimal(current_epoch, "current_authority_epoch", 0)
        if (old_epoch != "141" || current_epoch != "142")
            fail("stale/current authority epochs changed: " $0)
        before = field("projection_before")
        after = field("projection_after")
        require_hex(before, "projection_before")
        require_hex(after, "projection_after")
        if (length(before) != 18 || before != after)
            fail("stale-authority rejection changed the Registry projection: " $0)
        cookie = field("flight_cookie")
        ticket = field("ticket_effect")
        request = field("causal_request")
        root = field("causal_root")
        require_postcommit_identity(cookie, ticket, request, root, "stale probe")
        stale_probe_line = FNR
    } else if (event == "WakeTrigger") {
        require_field("runner", "fsd-v3")
        require_field("trigger_task", "951")
        require_field("trigger_generation", "3")
        require_field("registry_replacement", "false")
        require_field("causal_service_task_facade_observed", "false")
        require_field("causal_fault_matrix_promotion", "false")
        require_field("causal_state", "Active")
        require_field("same_causal_session", "true")
        require_field("same_flight", "true")
        require_field("same_ticket", "true")
        require_field("same_outcome", "true")
        require_field("reply_wakeups", "1")
        require_field("exactly_once", "true")
        require_field("original_guest_publication_pending", "true")
        require_field("recommit", "false")
        require_field("rebind", "false")
        require_field("adopt", "false")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        cookie = field("flight_cookie")
        ticket = field("ticket_effect")
        request = field("causal_request")
        root = field("causal_root")
        require_postcommit_identity(cookie, ticket, request, root, "wake trigger")
        wake_trigger_line = FNR
    } else if (event == "CausalPublication") {
        require_field("before_close", "Active")
        require_field("after_close", "Closed")
        require_field("outer_ack_apply", "true")
        require_field("after_outer_ack", "Vacant")
        require_field("publication_actor", "original_guest")
        cookie = field("flight_cookie")
        ticket = field("ticket_effect")
        request = field("causal_request")
        root = field("causal_root")
        require_postcommit_identity(cookie, ticket, request, root, "causal publication")
        causal_publication_line = FNR
    } else if (event == "GuestPublication") {
        require_field("actor", "original_guest")
        require_field("trigger", "fsd-v3")
        require_field("result", "4")
        require_field("bytes", "4")
        require_field("source", "CompletedRequest")
        require_field("registry_ack", "true")
        require_field("revoke_complete", "true")
        require_field("causal_state", "Vacant")
        postcommit_guest_publication_line = FNR
    } else if (event == "PASS") {
        require_field("post_backend_pre_reply_crash", "true")
        require_field("prebackend_crash", "false")
        require_field("v2_real_user_page_fault", "true")
        require_field("v3_fresh_closure_trigger", "true")
        require_field("v3_registry_replacement", "false")
        require_field("v3_registry_task", "false")
        require_field("causal_service_task_facade_observed", "false")
        require_field("causal_fault_matrix_promotion", "false")
        require_field("phase", "Revoked")
        require_field("live_effects", "0")
        require_field("pending_publications", "0")
        require_field("publication_acks", "1")
        require_field("terminalizations", "6")
        require_field("same_flight", "true")
        require_field("same_ticket", "true")
        require_field("same_outcome", "true")
        require_field("same_causal_session", "true")
        require_field("causal_before_v2_crash", "Active")
        require_field("causal_before_stale_probe", "Active")
        require_field("causal_before_wake_trigger", "Active")
        require_field("causal_publication_transition", "Active,Closed,Vacant")
        require_field("stale_v2_authority", "StaleAuthority")
        require_field("registry_projection_unchanged", "true")
        require_field("flight_identity_unchanged", "true")
        require_field("causal_identity_unchanged", "true")
        require_field("recommit", "false")
        require_field("rebind", "false")
        require_field("adopt", "false")
        require_field("reply_wakeups", "1")
        require_field("exactly_once", "true")
        require_field("publication_actor", "original_guest")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        require_field("quiescent", "true")
        postcommit_pass_line = FNR
    } else {
        fail("unknown postcommit receipt: " $0)
    }
}

function parse_fsd_exit() {
    if ($1 == "FSD_V2_POSTCOMMIT") {
        if ($2 != "EXIT")
            fail("malformed postcommit V2 termination: " $0)
        require_field("task", "951")
        require_field("task_generation", "2")
        require_field("reason", "real_user_page_fault")
        require_field("addr", "0x800000")
        require_field("device_committed", "true")
        require_field("backend_completed", "true")
        require_field("flight", "AwaitingPublication")
        require_field("causal_state", "Active")
        require_field("guest_reply", "false")
        require_field("reply_wakeups", "0")
        v2_exit_count++
        v2_exit_line = FNR
    } else if ($1 == "FSD_V3") {
        if ($2 != "EXIT")
            fail("malformed postcommit V3 termination: " $0)
        require_field("task", "951")
        require_field("task_generation", "3")
        require_field("reason", "postcommit_closure_trigger_done")
        require_field("registry_replacement", "false")
        require_field("stale_probe", "true")
        require_field("recommit", "false")
        require_field("rebind", "false")
        require_field("adopt", "false")
        require_field("reply_wakeups", "1")
        v3_exit_count++
        v3_exit_line = FNR
    }
}

function parse_serial_line() {
    sub(/\r$/, "")
    if ($0 ~ /panicked at|Non-resettable panic!|vtd_dmar_fault/)
        fail("forbidden failure in serial input: " $0)
    if ($0 ~ /prebackend_crash=true|lost_ack=true|outer_ack_failure(_observed)?=true|causal_service_task_facade_observed=true|causal_fault_matrix_promotion=true|registry_replacement=true|v3_registry_replacement=true/)
        fail("postcommit receipt overstates the bounded runtime claim: " $0)
    if ($0 ~ /irq=true|smp=[23456789][0-9]*/)
        fail("postcommit receipt overstates IRQ/SMP evidence: " $0)
    if ($0 ~ /^(LINUX_NET_SLICE|LINUX_IO_COMPOSITION|COMPOSITION_|IOMMU_PROBE)/)
        fail("legacy successor executed in postcommit feature run: " $0)
    if ($0 ~ /^(virtio_set_status|virtio_pci_notify_write|virtio_queue_notify|virtio_blk_|blk_co_pwritev|vtd_)/)
        fail("QEMU debug trace leaked into serial input: " $0)

    if ($0 ~ /^LINUX_FS_POSTCOMMIT /) {
        parse_postcommit()
        return
    }
    if ($0 ~ /^(FSD_V2_POSTCOMMIT|FSD_V3) EXIT /) {
        parse_fsd_exit()
        return
    }
    if ($0 ~ /^LINUX_FS_SLICE CLOSED /)
        fail("postcommit witness reported only an early closed slice: " $0)
    if ($0 ~ /^LINUX_FS_SLICE PASS /) {
        require_field("registry", "shared_production")
        require_field("production_effects", "6")
        require_field("real_user_service_crash", "true")
        require_field("no_synthetic_cohort", "true")
        require_field("registry_quiescent", "true")
        require_field("single_cpu", "true")
        require_field("device_commit", "true")
        require_field("real_dma", "true")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        require_field("same_boot", "true")
        require_field("identity_preserving", "true")
        slice_pass_count++
        slice_pass_line = FNR
        return
    }
    if ($0 ~ /^RUNTIME_FS_SAME_BOOT_POSTCOMMIT_FIXTURE /) {
        fixture = "RUNTIME_FS_SAME_BOOT_POSTCOMMIT_FIXTURE before=" image_sha \
            " after=" image_sha " mode=444 readonly=true"
        if ($0 != fixture)
            fail("malformed or changed immutable fixture receipt: " $0)
        fixture_count++
        fixture_line = FNR
        return
    }
    if ($0 ~ /^SPIKE_RESULT /) {
        if ($0 != "SPIKE_RESULT PASS")
            fail("malformed feature terminal result: " $0)
        spike_count++
        spike_line = FNR
        return
    }
    if ($0 !~ /^LINUX_FS_SAME_BOOT /)
        return

    if ($2 == "Capture") {
        parse_capture()
    } else if ($2 == "DmaOwner") {
        parse_dma_owner()
    } else if ($2 == "Commit") {
        parse_commit()
    } else if ($2 == "Notify") {
        require_device_event("Notify")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        notify_disposition = field("disposition")
        if (notify_disposition != "Kicked" && notify_disposition != "Suppressed")
            fail("unexpected notification disposition: " notify_disposition)
    } else if ($2 == "Completion") {
        require_device_event("Completion")
        if ($0 != "LINUX_FS_SAME_BOOT Completion outcome=Completed result=4 used_len=513 payload_source=CompletedRequest data_prefix=7f454c46")
            fail("postcommit gate requires the exact backend completion: " $0)
        backend_completion_line = FNR
    } else if ($2 == "ResetTimeout") {
        require_device_event("ResetTimeout")
        if ($0 != "LINUX_FS_SAME_BOOT ResetTimeout registry_tombstone=true hardware_tombstone=true retained_pages=3 generation=1")
            fail("malformed ResetTimeout receipt: " $0)
    } else if ($2 == "ResetAck") {
        require_device_event("ResetAck")
        if ($0 != "LINUX_FS_SAME_BOOT ResetAck generation=1->2 outcome=Completed retained_pages=3 generation_apply_atomic=true")
            fail("malformed ResetAck receipt: " $0)
    } else if ($2 == "IotlbTimeout") {
        require_device_event("IotlbTimeout")
        if ($0 != "LINUX_FS_SAME_BOOT IotlbTimeout registry_generation=2 hardware_identity_generation=1 retained_pages=3 registry_tombstone=true hardware_tombstone=true")
            fail("malformed IotlbTimeout receipt: " $0)
    } else if ($2 == "IotlbAck") {
        require_device_event("IotlbAck")
        if ($0 != "LINUX_FS_SAME_BOOT IotlbAck completed_pages=3 registry_generation=2 hardware_identity_generation=1 quiescence_applied=true")
            fail("malformed IotlbAck receipt: " $0)
    } else if ($2 == "Close") {
        require_device_event("Close")
        if ($0 != "LINUX_FS_SAME_BOOT Close leaf_first=dma_queue_owner_a,dma_queue_owner_b,dma_request_owner,block_request,filesystem_read,filesystem_syscall terminal_outcome=Completed guest_publication_pending=true")
            fail("malformed leaf-first Close receipt: " $0)
        close_line = FNR
    } else if ($2 == "GuestPublication") {
        require_device_event("GuestPublication")
        if ($0 != "LINUX_FS_SAME_BOOT GuestPublication result=4 bytes=4 source=CompletedRequest registry_ack=true revoke_complete=true")
            fail("malformed guest publication receipt: " $0)
        guest_publication_line = FNR
    } else if ($2 == "PASS") {
        require_device_event("PASS")
        require_field("same_boot", "true")
        require_field("identity_preserving", "true")
        require_field("real_dma", "true")
        require_field("polling", "true")
        require_field("irq", "false")
        require_field("smp", "1")
        require_field("scope", "95")
        require_field("effects", "6")
        require_field("credits", "10")
        require_field("sector_sha256", sector_sha)
        require_field("image_sha256", image_sha)
        require_field("sector_fnv1a", "0x33913395b7798e6b")
        device_pass_line = FNR
    } else {
        fail("unknown same-boot device receipt: " $0)
    }
}

function validate_serial() {
    if (serial_validated || failed)
        return
    serial_validated = 1
    if (device_events != 14 || owners != 3)
        fail("expected 14 device receipts and three DMA owners, observed " \
             device_events "/" owners)
    if (postcommit_events != 8)
        fail("expected eight ordered postcommit receipts, observed " postcommit_events)
    if (v2_exit_count != 1 || v3_exit_count != 1)
        fail("expected one V2 crash exit and one V3 closure-trigger exit")
    if (slice_pass_count != 1 || fixture_count != 1 || spike_count != 1)
        fail("expected one slice PASS, fixture receipt, and SPIKE_RESULT")
    if (!begin_line || !backend_completion_line || !close_line || !crash_line ||
        !v2_exit_line || !fresh_trigger_line || !stale_probe_line ||
        !wake_trigger_line || !v3_exit_line || !causal_publication_line ||
        !postcommit_guest_publication_line || !guest_publication_line ||
        !device_pass_line || !slice_pass_line || !postcommit_pass_line ||
        !spike_line || !fixture_line ||
        !(begin_line < backend_completion_line &&
          backend_completion_line < close_line && close_line < crash_line &&
          crash_line < v2_exit_line && v2_exit_line < fresh_trigger_line &&
          fresh_trigger_line < stale_probe_line &&
          stale_probe_line < wake_trigger_line && wake_trigger_line < v3_exit_line &&
          v3_exit_line < causal_publication_line &&
          causal_publication_line < postcommit_guest_publication_line &&
          postcommit_guest_publication_line < guest_publication_line &&
          guest_publication_line < device_pass_line &&
          device_pass_line < slice_pass_line &&
          slice_pass_line < postcommit_pass_line &&
          postcommit_pass_line < spike_line && spike_line < fixture_line))
        fail("post-backend crash, original publication, and closure order is invalid")
}

function token_after(name,    i) {
    for (i = 1; i < NF; i++)
        if ($i == name)
            return $(i + 1)
    return ""
}

function add_control(value, vdev, req) {
    control[++controls] = value
    control_line[controls] = FNR
    control_vdev[controls] = vdev
    control_req[controls] = req
}

function add_expected(position, value) {
    expected_control[position] = value
    expected_positions[++expected_controls] = position
}

function parse_debug_line(    vdev, req, queue, vq, iova, gpa, kind) {
    sub(/\r$/, "")
    if ($0 ~ /^(LINUX_FS_|FSD_V[123]|SPIKE_RESULT |RUNTIME_FS_)/)
        fail("guest serial receipt leaked into QEMU debug input: " $0)
    if ($0 ~ /virtio_blk_handle_write|blk_co_pwritev|vtd_dmar_fault|panicked at|Non-resettable panic!/)
        fail("write, DMAR fault, or panic entered the readonly postcommit run: " $0)

    if ($1 == "virtio_set_status") {
        vdev = token_after("vdev")
        if (vdev !~ /^0x[0-9a-f]+$/ || $NF !~ /^[0-9]+$/)
            fail("malformed VirtIO status event: " $0)
        add_control("status:" $NF, vdev, "")
    } else if ($1 == "virtio_pci_notify_write") {
        add_control("notify", "", "")
        activity[++activities] = "notify"
        activity_line[activities] = FNR
    } else if ($1 == "virtio_queue_notify") {
        vdev = token_after("vdev")
        queue = token_after("n")
        vq = token_after("vq")
        if (vdev !~ /^0x[0-9a-f]+$/ || queue != "0" || vq !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO queue notification: " $0)
        add_control("queue", vdev, "")
        activity[++activities] = "queue"
        activity_line[activities] = FNR
    } else if ($1 == "virtio_blk_handle_read") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO read event: " $0)
        add_control($0 ~ / sector 0 nsectors 1$/ ? "read:sector0:1" : "read:other", vdev, req)
        activity[++activities] = "read"
        activity_line[activities] = FNR
    } else if ($1 == "virtio_blk_rw_complete") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO backend completion: " $0)
        add_control($0 ~ / ret 0$/ ? "rw_complete:0" : "rw_complete:error", vdev, req)
        activity[++activities] = "rw_complete"
        activity_line[activities] = FNR
    } else if ($1 == "virtio_blk_req_complete") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO request completion: " $0)
        add_control($0 ~ / status 0$/ ? "req_complete:0" : "req_complete:error", vdev, req)
        activity[++activities] = "req_complete"
        activity_line[activities] = FNR
    } else if ($1 == "vtd_inv_desc_iotlb_global") {
        add_control("iotlb_global", "", "")
        iotlb_globals++
    } else if ($1 == "vtd_inv_desc_wait_irq") {
        add_control("iotlb_wait", "", "")
        iotlb_waits++
    } else if ($1 == "vtd_dmar_translate") {
        activity[++activities] = "translate"
        activity_line[activities] = FNR
        iova = $5
        gpa = $8
        if (iova in owner_kind_by_iova) {
            kind = owner_kind_by_iova[iova]
            if ($3 != "00:05.00" || gpa != owner_paddr[kind] || iova == gpa)
                fail("owned IOVA translated to the wrong BDF or paddr: " $0)
            seen_owner[kind] = 1
            if (!first_owned_line) {
                first_owned_line = FNR
                controls_before_first_owned = controls
            }
            last_owned_line = FNR
        }
    }
}

function validate_debug(    prefix, start, position, read_position, rw_position,
                           req_position, reset_position, target_end, target_vdev,
                           target_req, kind, i) {
    if (debug_validated || failed)
        return
    debug_validated = 1
    if (!first_owned_line)
        fail("missing QEMU translation for the exact Registry DMA owners")
    for (kind in owner_iova)
        if (!(kind in seen_owner))
            fail("Registry DMA owner was not translated by QEMU: " kind)

    prefix = notify_disposition == "Kicked" ? 7 : 5
    start = controls_before_first_owned - prefix + 1
    if (start < 1)
        fail("owned-I/O anchor has no complete device initialization prefix")
    position = start
    add_expected(position++, "status:0")
    add_expected(position++, "status:0")
    add_expected(position++, "status:3")
    add_expected(position++, "status:11")
    add_expected(position++, "status:15")
    if (notify_disposition == "Kicked") {
        add_expected(position++, "notify")
        add_expected(position++, "queue")
    }
    read_position = position
    add_expected(position++, "read:sector0:1")
    rw_position = position
    add_expected(position++, "rw_complete:0")
    req_position = position
    add_expected(position++, "req_complete:0")
    reset_position = position
    for (i = 0; i < 5; i++)
        add_expected(position++, "status:0")
    for (i = 0; i < 3; i++) {
        add_expected(position++, "iotlb_global")
        add_expected(position++, "iotlb_wait")
    }
    target_end = position - 1

    for (i = 1; i <= expected_controls; i++) {
        position = expected_positions[i]
        if (control[position] != expected_control[position])
            fail("target control event " position " expected " expected_control[position] \
                 ", observed " control[position])
    }
    target_vdev = control_vdev[start]
    target_req = control_req[read_position]
    if (target_vdev !~ /^0x[0-9a-f]+$/ || target_req !~ /^0x[0-9a-f]+$/)
        fail("target request has no valid vdev/request identity")
    for (i = start; i <= target_end; i++)
        if (control_vdev[i] != "" && control_vdev[i] != target_vdev)
            fail("target control sequence changed vdev at event " i)
    if (control_req[rw_position] != target_req || control_req[req_position] != target_req)
        fail("target read/completion sequence changed request identity")
    if (first_owned_line <= control_line[start + prefix - 1] ||
        last_owned_line >= control_line[reset_position])
        fail("owned DMA translations escaped the publish/completion window")
    if (iotlb_globals != 3 || iotlb_waits != 3)
        fail("expected one exact three-owner IOTLB completion chain")
    for (i = 1; i <= activities; i++) {
        if (activity_line[i] > control_line[target_end])
            fail("device activity after IOTLB acknowledgement: " activity[i])
        if (activity_line[i] >= control_line[reset_position] &&
            activity[i] == "translate")
            fail("DMA translation remained live after reset began")
    }
    for (i = target_end + 1; i <= controls; i++)
        if (control[i] != "status:0" || control_vdev[i] != target_vdev)
            fail("unexpected control event after target quiescence: " control[i])
}

BEGIN {
    image_sha = "9357413ed9a96a23af1750cc304265dd7dd1835eb58eb1fb50119cd80d0bc8ca"
    sector_sha = "4fb2b63ca7d483c6efaa756182133f05c7ef453fa82e94ce31826ebc4c104f66"
    expected_device_event[1] = "Capture"
    expected_device_event[2] = "DmaOwner"
    expected_device_event[3] = "DmaOwner"
    expected_device_event[4] = "DmaOwner"
    expected_device_event[5] = "Commit"
    expected_device_event[6] = "Notify"
    expected_device_event[7] = "Completion"
    expected_device_event[8] = "ResetTimeout"
    expected_device_event[9] = "ResetAck"
    expected_device_event[10] = "IotlbTimeout"
    expected_device_event[11] = "IotlbAck"
    expected_device_event[12] = "Close"
    expected_device_event[13] = "GuestPublication"
    expected_device_event[14] = "PASS"
    expected_owner_kind[1] = "queue_driver"
    expected_owner_kind[2] = "queue_device"
    expected_owner_kind[3] = "request"
    expected_postcommit_event[1] = "BEGIN"
    expected_postcommit_event[2] = "Crash"
    expected_postcommit_event[3] = "FreshTrigger"
    expected_postcommit_event[4] = "StaleProbe"
    expected_postcommit_event[5] = "WakeTrigger"
    expected_postcommit_event[6] = "CausalPublication"
    expected_postcommit_event[7] = "GuestPublication"
    expected_postcommit_event[8] = "PASS"
}

NR == FNR {
    parse_serial_line()
    next
}

{
    validate_serial()
    parse_debug_line()
}

END {
    # `./x check` uses an empty-input call as a parser-only syntax gate.
    if (NR == 0)
        exit 0
    if (failed)
        exit 1
    validate_serial()
    validate_debug()
}
