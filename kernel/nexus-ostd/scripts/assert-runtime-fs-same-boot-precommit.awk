# SPDX-License-Identifier: MPL-2.0

function fail(message) {
    print "runtime filesystem same-boot precommit assertion failed: " message > "/dev/stderr"
    failed = 1
    exit 1
}

function value_at(position, name,    prefix, token) {
    prefix = name "="
    token = $(position)
    if (index(token, prefix) != 1)
        fail("expected field " name " at serial position " position ": " $0)
    return substr(token, length(prefix) + 1)
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

function require_canonical_hex(value, label) {
    if (value !~ /^0x(0|[1-9a-f][0-9a-f]*)$/)
        fail("malformed canonical lowercase hexadecimal " label "=" value)
}

function require_page_address(value, label) {
    if (value !~ /^0x[1-9a-f][0-9a-f]*000$/)
        fail("non-canonical, zero, or unaligned page address " label "=" value)
}

function require_event(name) {
    serial_events++
    if (expected_event[serial_events] != name)
        fail("serial event " serial_events " expected " expected_event[serial_events] \
             ", observed " name)
}

function add_effect(effect, label) {
    require_decimal(effect, label, 0)
    if (effect in effect_label)
        fail("duplicate effect identity " effect " for " label " and " effect_label[effect])
    effect_label[effect] = label
    effect_count++
}

function parse_capture(    session) {
    require_event("Capture")
    if (NF != 13 || $3 != "stage=enrolled_preflight" || $4 != "scope=95" ||
        $5 != "effects=6" || $6 != "credits=10" ||
        $7 != "registry=shared_production" ||
        $8 != "fault=revoke_wins_commit_gate" || $9 != "device=00:05.0" ||
        $11 != "generation=1" || $12 != "queue=0")
        fail("malformed precommit Capture receipt: " $0)
    session = value_at(10, "session")
    require_hex(session, "session")
    if (length(session) != 18)
        fail("device session is not a 64-bit hexadecimal identity: " session)
    descriptor = value_at(13, "descriptor")
    require_decimal(descriptor, "descriptor", 1)
    capture_line = FNR
}

function parse_dma_owner(    position, kind, effect, paddr, iova) {
    require_event("DmaOwner")
    if (NF != 10 || $7 != "page_size=4096" || $8 != "queue=0" ||
        $10 != "generation=1")
        fail("malformed precommit DmaOwner receipt: " $0)
    position = serial_events - 1
    kind = value_at(3, "kind")
    if (kind != expected_owner_kind[position])
        fail("DMA owner " position " expected kind=" expected_owner_kind[position] \
             ", observed " kind)
    effect = value_at(4, "effect")
    add_effect(effect, kind)
    paddr = value_at(5, "paddr")
    iova = value_at(6, "iova")
    require_page_address(paddr, kind "_paddr")
    require_page_address(iova, kind "_iova")
    if (paddr == iova || paddr in owner_kind_by_paddr ||
        paddr in owner_kind_by_iova || iova in owner_kind_by_paddr ||
        iova in owner_kind_by_iova)
        fail("duplicate or identity-mapped prepared DMA owner: " $0)
    if (value_at(9, "descriptor") != descriptor)
        fail("DMA owner descriptor does not match precommit Capture: " $0)
    owner_effect[kind] = effect
    owner_paddr[kind] = paddr
    owner_iova[kind] = iova
    owner_kind_by_paddr[paddr] = kind
    owner_kind_by_iova[iova] = kind
    owners++
}

function parse_abort(    ordinal, kind, effect) {
    require_event("Abort")
    if (NF != 7 || $6 != "result=-125" || $7 != "leaf_first=true")
        fail("malformed precommit Abort receipt: " $0)
    ordinal = value_at(3, "ordinal")
    require_decimal(ordinal, "abort_ordinal", 0)
    if (ordinal != aborts + 1)
        fail("precommit Abort ordinal is not contiguous: " $0)
    kind = value_at(4, "kind")
    if (kind != expected_abort_kind[ordinal])
        fail("precommit Abort ordinal " ordinal " expected kind=" \
             expected_abort_kind[ordinal] ", observed " kind)
    effect = value_at(5, "effect")
    if (ordinal == 1 && effect != owner_effect["queue_driver"])
        fail("queue-driver Abort does not match prepared owner effect")
    if (ordinal == 2 && effect != owner_effect["queue_device"])
        fail("queue-device Abort does not match prepared owner effect")
    if (ordinal == 3 && effect != owner_effect["request"])
        fail("request Abort does not match prepared owner effect")
    if (ordinal > 3)
        add_effect(effect, kind)
    abort_effect[ordinal] = effect
    aborts++
}

function parse_serial_line() {
    sub(/\r$/, "")
    if ($0 ~ /panicked at|Non-resettable panic!|vtd_dmar_fault/)
        fail("forbidden failure in precommit serial input: " $0)
    if ($0 ~ /^(LINUX_NET_SLICE|LINUX_IO_COMPOSITION|COMPOSITION_|IOMMU_PROBE)/)
        fail("legacy successor executed in precommit feature run: " $0)
    if ($0 ~ /^LINUX_FS_SAME_BOOT / || $0 ~ /avail_idx_release/ ||
        $0 ~ /source=CompletedRequest|data_prefix=7f454c46/)
        fail("published positive-path evidence leaked into precommit run: " $0)
    if ($0 ~ /^(virtio_set_status|virtio_pci_notify_write|virtio_queue_notify|virtio_blk_|blk_co_pwritev|vtd_)/)
        fail("QEMU debug trace leaked into precommit serial input: " $0)

    if ($0 ~ /^LINUX_FS_SLICE CLOSED /)
        fail("accepted precommit witness reported only an early closed slice: " $0)
    if ($0 ~ /^LINUX_FS_SLICE PASS /) {
        expected_slice_pass = "LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=2 compatibility_syscalls=payload_only_not_cser openat=1 pread64=1 registry=shared_production commit_gate=revoke_wins publication_acks=1 production_root=true production_domains=3 production_effects=6 immutable_ancestry=true filesystem_registry_domain_crash_adopt=true real_user_service_crash=false no_synthetic_cohort=true typed_credit_classes=6 leaf_first=true registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true block_adapter=virtio_blk device_commit=false real_dma_prepared=true device_dma_observed=false polling=false irq=false smp=1 same_boot=true identity_preserving=true precommit_fault=true"
        if ($0 != expected_slice_pass)
            fail("malformed or non-success aggregate filesystem result: " $0)
        slice_pass_count++
        if (slice_pass_count != 1)
            fail("duplicate aggregate filesystem PASS")
        slice_pass_line = FNR
        return
    }

    if ($0 ~ /^RUNTIME_FS_SAME_BOOT_PRECOMMIT_FIXTURE /) {
        fixture = "RUNTIME_FS_SAME_BOOT_PRECOMMIT_FIXTURE before=" image_sha \
            " after=" image_sha " mode=444 readonly=true"
        if ($0 != fixture)
            fail("malformed or changed precommit fixture receipt: " $0)
        fixture_count++
        fixture_line = FNR
        return
    }
    if ($0 ~ /^SPIKE_RESULT /) {
        if ($0 != "SPIKE_RESULT PASS")
            fail("malformed precommit feature terminal result: " $0)
        spike_count++
        spike_line = FNR
        return
    }
    if ($0 !~ /^LINUX_FS_SAME_BOOT_PRECOMMIT /)
        return

    if ($2 == "Capture") {
        parse_capture()
    } else if ($2 == "DmaOwner") {
        parse_dma_owner()
    } else if ($2 == "CommitGate") {
        require_event("CommitGate")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT CommitGate winner=revoke stage=precommit_commit_gate publish_closure_calls=0 device_visible=false")
            fail("malformed precommit CommitGate receipt: " $0)
    } else if ($2 == "ResetTimeout") {
        require_event("ResetTimeout")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT ResetTimeout registry_tombstone=true hardware_tombstone=true retained_pages=3 generation=1")
            fail("malformed precommit ResetTimeout receipt: " $0)
    } else if ($2 == "ResetAck") {
        require_event("ResetAck")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT ResetAck generation=1->2 outcome=AbortedBeforeCommit retained_pages=3 was_published=false descriptor_popped=false completed=false generation_apply_atomic=true")
            fail("malformed precommit ResetAck receipt: " $0)
    } else if ($2 == "IotlbTimeout") {
        require_event("IotlbTimeout")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT IotlbTimeout registry_generation=2 hardware_identity_generation=1 retained_pages=3 registry_tombstone=true hardware_tombstone=true")
            fail("malformed precommit IotlbTimeout receipt: " $0)
    } else if ($2 == "IotlbAck") {
        require_event("IotlbAck")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT IotlbAck completed_pages=3 registry_generation=2 hardware_identity_generation=1 outcome=AbortedBeforeCommit quiescence_apply_atomic=true")
            fail("malformed precommit IotlbAck receipt: " $0)
    } else if ($2 == "Abort") {
        parse_abort()
    } else if ($2 == "Close") {
        require_event("Close")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT Close leaf_first=dma_queue_owner_a,dma_queue_owner_b,dma_request_owner,block_request,filesystem_read,filesystem_syscall closure=AbortedBeforeCommit guest_publication_pending=true")
            fail("malformed precommit Close receipt: " $0)
    } else if ($2 == "GuestPublication") {
        require_event("GuestPublication")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT GuestPublication result=-125 bytes=0 source=none registry_ack=true revoke_complete=true")
            fail("malformed precommit GuestPublication receipt: " $0)
    } else if ($2 == "PASS") {
        require_event("PASS")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT PASS scope=95 effects=6 credits_free=10 live_effects=0 pending_publications=0 closure=AbortedBeforeCommit publish_closure_calls=0 prepared_owner_retained=true was_published=false guest_bytes=0 leaf_first=true")
            fail("malformed terminal precommit result: " $0)
        pass_line = FNR
    } else if ($2 == "Terminal") {
        require_event("Terminal")
        if ($0 != "LINUX_FS_SAME_BOOT_PRECOMMIT Terminal receipt_checked=true registry=shared_production compatibility_syscalls=payload_only_not_cser poweroff=success")
            fail("malformed precommit kernel-root terminal receipt: " $0)
        terminal_line = FNR
    } else {
        fail("unknown precommit serial receipt: " $0)
    }
}

function validate_serial() {
    if (serial_validated || failed)
        return
    serial_validated = 1
    if (serial_events != 19)
        fail("expected 19 ordered precommit receipts, observed " serial_events)
    if (owners != 3 || aborts != 6)
        fail("expected three owners and six leaf-first Aborts, observed " owners "/" aborts)
    if (effect_count != 6)
        fail("expected six unique precommit effect identities, observed " effect_count)
    if (slice_pass_count != 1 || fixture_count != 1 || spike_count != 1)
        fail("expected one aggregate PASS, one SPIKE_RESULT, and one immutable fixture receipt")
    if (!capture_line || !pass_line || !slice_pass_line || !terminal_line ||
        !spike_line ||
        !(capture_line < pass_line && pass_line < slice_pass_line &&
          slice_pass_line < terminal_line && terminal_line < spike_line &&
          spike_line < fixture_line))
        fail("precommit Capture/PASS/Terminal/SPIKE_RESULT/fixture order is incomplete or invalid")
}

function token_after(name,    i) {
    for (i = 1; i < NF; i++) {
        if ($i == name)
            return $(i + 1)
    }
    return ""
}

function add_control(value, vdev) {
    control[++controls] = value
    control_line[controls] = FNR
    control_vdev[controls] = vdev
}

function parse_debug_line(    vdev, queue, vq, iova) {
    sub(/\r$/, "")
    if ($0 ~ /^(LINUX_FS_|SPIKE_RESULT |RUNTIME_FS_|EFFECT_REGISTRY )/)
        fail("guest serial receipt leaked into precommit QEMU debug input: " $0)
    if ($0 ~ /virtio_blk_handle_write|blk_co_pwritev|vtd_dmar_fault|panicked at|Non-resettable panic!/)
        fail("forbidden precommit QEMU/device trace: " $0)

    if ($1 == "virtio_set_status") {
        if (NF != 5 || $2 != "vdev" || $4 != "val")
            fail("malformed VirtIO status event: " $0)
        vdev = $3
        require_canonical_hex(vdev, "status_vdev")
        require_decimal($5, "status", 1)
        add_control("status:" $5, vdev)
        return
    }
    if ($1 == "virtio_pci_notify_write") {
        if ($0 != "virtio_pci_notify_write 0x0 = 0x0 (2)")
            fail("malformed VirtIO PCI notification: " $0)
        add_control("notify", "")
        activity[++activities] = "notify"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_queue_notify") {
        if (NF != 7 || $2 != "vdev" || $4 != "n" || $6 != "vq")
            fail("malformed VirtIO queue notification: " $0)
        vdev = $3
        queue = $5
        vq = $7
        require_canonical_hex(vdev, "queue_vdev")
        require_decimal(queue, "queue", 1)
        require_canonical_hex(vq, "queue_vq")
        if (queue != "0")
            fail("unexpected VirtIO queue notification: " $0)
        add_control("queue", vdev)
        activity[++activities] = "queue"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_blk_handle_read") {
        if (NF != 9 || $2 != "vdev" || $4 != "req" ||
            $6 != "sector" || $8 != "nsectors")
            fail("malformed VirtIO read event: " $0)
        require_canonical_hex($3, "read_vdev")
        require_canonical_hex($5, "read_req")
        require_decimal($7, "read_sector", 1)
        require_decimal($9, "read_nsectors", 0)
        add_control("read", $3)
        activity[++activities] = "read"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_blk_rw_complete") {
        if (NF != 7 || $2 != "vdev" || $4 != "req" || $6 != "ret")
            fail("malformed VirtIO backend completion: " $0)
        require_canonical_hex($3, "completion_vdev")
        require_canonical_hex($5, "completion_req")
        if ($7 !~ /^-?(0|[1-9][0-9]*)$/)
            fail("malformed VirtIO backend result: " $0)
        add_control("completion", $3)
        activity[++activities] = "completion"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_blk_req_complete") {
        if (NF != 7 || $2 != "vdev" || $4 != "req" || $6 != "status")
            fail("malformed VirtIO request completion: " $0)
        require_canonical_hex($3, "request_completion_vdev")
        require_canonical_hex($5, "request_completion_req")
        require_decimal($7, "request_completion_status", 1)
        add_control("completion", $3)
        activity[++activities] = "completion"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "vtd_inv_desc_iotlb_global") {
        if ($0 != "vtd_inv_desc_iotlb_global iotlb invalidate global")
            fail("malformed IOTLB global invalidation: " $0)
        add_control("iotlb_global", "")
        iotlb_globals++
        return
    }
    if ($1 == "vtd_inv_desc_wait_irq") {
        if ($0 != "vtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated")
            fail("malformed IOTLB wait acknowledgement: " $0)
        add_control("iotlb_wait", "")
        iotlb_waits++
        return
    }
    if ($1 == "vtd_dmar_translate") {
        if (NF != 10 || $2 != "dev" ||
            $3 !~ /^[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]\.[0-9a-f][0-9a-f]$/ ||
            $4 != "iova" || $6 != "->" || $7 != "gpa" || $9 != "mask")
            fail("malformed VT-d translation: " $0)
        iova = $5
        require_canonical_hex(iova, "translation_iova")
        require_canonical_hex($8, "translation_gpa")
        require_canonical_hex($10, "translation_mask")
        activity[++activities] = "translate"
        activity_line[activities] = FNR
        if (iova in owner_kind_by_iova)
            fail("unpublished prepared owner reached device DMA translation: " \
                 owner_kind_by_iova[iova] " " $0)
    }
}

function candidate_at(start,    vdev, i, position) {
    if (control[start] != "status:0" || control[start + 1] != "status:0" ||
        control[start + 2] != "status:0" || control[start + 3] != "status:0" ||
        control[start + 4] != "status:3" || control[start + 5] != "status:11" ||
        control[start + 6] != "status:15")
        return 0
    vdev = control_vdev[start]
    if (vdev !~ /^0x[0-9a-f]+$/)
        return 0
    for (i = 0; i < 12; i++) {
        position = start + i
        if (control_vdev[position] != vdev)
            return 0
        if (i >= 7 && control[position] != "status:0")
            return 0
    }
    for (i = 0; i < 3; i++) {
        if (control[start + 12 + i * 2] != "iotlb_global" ||
            control[start + 13 + i * 2] != "iotlb_wait")
            return 0
    }
    return 1
}

function validate_debug(    start, candidate, target_end, target_vdev, i) {
    if (debug_validated || failed)
        return
    debug_validated = 1
    if (iotlb_globals != 3 || iotlb_waits != 3)
        fail("expected one exact three-owner precommit IOTLB chain")

    for (start = 1; start + 17 <= controls; start++) {
        if (candidate_at(start)) {
            candidates++
            candidate = start
        }
    }
    if (candidates != 1)
        fail("expected one unpublished init/reset/IOTLB control suffix, observed " candidates)
    target_end = candidate + 17
    target_vdev = control_vdev[candidate]

    for (i = 1; i <= activities; i++) {
        if (activity_line[i] > control_line[candidate])
            fail("device activity entered unpublished target window: " activity[i])
    }
    for (i = target_end + 1; i <= controls; i++) {
        if (control[i] != "status:0" || control_vdev[i] != target_vdev)
            fail("unexpected control event after precommit quiescence: " control[i])
    }
}

BEGIN {
    image_sha = "9357413ed9a96a23af1750cc304265dd7dd1835eb58eb1fb50119cd80d0bc8ca"
    expected_event[1] = "Capture"
    expected_event[2] = "DmaOwner"
    expected_event[3] = "DmaOwner"
    expected_event[4] = "DmaOwner"
    expected_event[5] = "CommitGate"
    expected_event[6] = "ResetTimeout"
    expected_event[7] = "ResetAck"
    expected_event[8] = "IotlbTimeout"
    expected_event[9] = "IotlbAck"
    for (i = 10; i <= 15; i++)
        expected_event[i] = "Abort"
    expected_event[16] = "Close"
    expected_event[17] = "GuestPublication"
    expected_event[18] = "PASS"
    expected_event[19] = "Terminal"
    expected_owner_kind[1] = "queue_driver"
    expected_owner_kind[2] = "queue_device"
    expected_owner_kind[3] = "request"
    expected_abort_kind[1] = "dma_queue_owner_a"
    expected_abort_kind[2] = "dma_queue_owner_b"
    expected_abort_kind[3] = "dma_request_owner"
    expected_abort_kind[4] = "block_request"
    expected_abort_kind[5] = "filesystem_read"
    expected_abort_kind[6] = "filesystem_syscall"
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
    if (NR == 0)
        exit 0
    if (failed)
        exit 1
    validate_serial()
    validate_debug()
}
