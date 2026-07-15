# SPDX-License-Identifier: MPL-2.0

function fail(message) {
    print "runtime filesystem same-boot assertion failed: " message > "/dev/stderr"
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
    if (value !~ /^[0-9]+$/ || (!allow_zero && value ~ /^0+$/))
        fail("malformed decimal " label "=" value)
}

function require_hex(value, label) {
    if (value !~ /^0x[0-9a-f]+$/)
        fail("malformed lowercase hexadecimal " label "=" value)
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
}

function parse_capture(    session) {
    require_event("Capture")
    if (NF != 18 || $3 != "same_boot=true" ||
        $4 != "identity_preserving=true" || $5 != "real_dma=true" ||
        $6 != "registry=shared_production" || $7 != "scope=95" ||
        $8 != "authority_epoch=141" || $9 != "effects=6" ||
        $10 != "credits=10" || $11 != "device=00:05.0" ||
        $13 != "generation=1" || $14 != "queue=0")
        fail("malformed Capture receipt: " $0)
    session = value_at(12, "session")
    require_hex(session, "session")
    if (length(session) != 18)
        fail("device session is not a 64-bit hexadecimal identity: " session)
    descriptor = value_at(15, "descriptor")
    require_decimal(descriptor, "descriptor", 1)
    syscall_effect = value_at(16, "syscall_effect")
    filesystem_effect = value_at(17, "filesystem_effect")
    block_effect = value_at(18, "block_effect")
    add_effect(syscall_effect, "filesystem_syscall")
    add_effect(filesystem_effect, "filesystem_read")
    add_effect(block_effect, "block_request")
    capture_line = FNR
}

function parse_dma_owner(    kind, effect, paddr, iova, owner_position) {
    require_event("DmaOwner")
    if (NF != 10 || $7 != "page_size=4096" || $8 != "queue=0" ||
        $10 != "generation=1")
        fail("malformed DmaOwner receipt: " $0)
    owner_position = serial_events - 1
    kind = value_at(3, "kind")
    if (kind != expected_owner_kind[owner_position])
        fail("DMA owner " owner_position " expected kind=" \
             expected_owner_kind[owner_position] ", observed " kind)
    effect = value_at(4, "effect")
    add_effect(effect, kind)
    paddr = value_at(5, "paddr")
    iova = value_at(6, "iova")
    require_hex(paddr, kind "_paddr")
    require_hex(iova, kind "_iova")
    if (paddr == iova)
        fail("DMA owner is identity mapped: " kind)
    if (paddr in owner_kind_by_paddr || paddr in owner_kind_by_iova ||
        iova in owner_kind_by_paddr || iova in owner_kind_by_iova)
        fail("duplicate DMA owner address identity: " $0)
    if (value_at(9, "descriptor") != descriptor)
        fail("DMA owner descriptor does not match Capture: " $0)
    owner_effect[kind] = effect
    owner_paddr[kind] = paddr
    owner_iova[kind] = iova
    owner_kind_by_paddr[paddr] = kind
    owner_kind_by_iova[iova] = kind
    owners++
}

function parse_commit(    batch) {
    require_event("Commit")
    if (NF != 12 || $4 != "commit_point=avail_idx_release" ||
        $11 != "publication_once=true" || $12 != "revoke_begin_immediate=true")
        fail("malformed Commit receipt: " $0)
    batch = value_at(3, "batch_sequence")
    require_decimal(batch, "batch_sequence", 0)
    if (value_at(5, "syscall_effect") != syscall_effect ||
        value_at(6, "filesystem_effect") != filesystem_effect ||
        value_at(7, "block_effect") != block_effect ||
        value_at(8, "dma_queue_owner_a_effect") != owner_effect["queue_driver"] ||
        value_at(9, "dma_queue_owner_b_effect") != owner_effect["queue_device"] ||
        value_at(10, "dma_request_owner_effect") != owner_effect["request"])
        fail("Commit effect cohort does not match Capture/DmaOwner receipts: " $0)
    commit_line = FNR
}

function parse_serial_line() {
    sub(/\r$/, "")
    if ($0 ~ /panicked at|Non-resettable panic!|vtd_dmar_fault/)
        fail("forbidden failure in serial input: " $0)
    if ($0 ~ /^(LINUX_NET_SLICE|LINUX_IO_COMPOSITION|COMPOSITION_|IOMMU_PROBE)/)
        fail("legacy successor executed in the same-boot feature run: " $0)
    if ($0 ~ /^(virtio_set_status|virtio_pci_notify_write|virtio_queue_notify|virtio_blk_|blk_co_pwritev|vtd_)/)
        fail("QEMU debug trace leaked into serial input: " $0)

    if ($0 ~ /^RUNTIME_FS_SAME_BOOT_FIXTURE /) {
        fixture = "RUNTIME_FS_SAME_BOOT_FIXTURE before=" image_sha \
            " after=" image_sha " mode=444 readonly=true"
        if ($0 != fixture)
            fail("malformed or changed immutable-fixture receipt: " $0)
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
        require_event("Notify")
        if (NF != 6 || $4 != "polling=true" || $5 != "irq=false" || $6 != "smp=1")
            fail("malformed Notify receipt: " $0)
        notify_disposition = value_at(3, "disposition")
        if (notify_disposition != "Kicked" && notify_disposition != "Suppressed")
            fail("unexpected notification disposition: " notify_disposition)
    } else if ($2 == "Completion") {
        require_event("Completion")
        if ($0 != "LINUX_FS_SAME_BOOT Completion outcome=Completed result=4 used_len=513 payload_source=CompletedRequest data_prefix=7f454c46")
            fail("same-boot acceptance requires the exact completed request: " $0)
    } else if ($2 == "ResetTimeout") {
        require_event("ResetTimeout")
        if ($0 != "LINUX_FS_SAME_BOOT ResetTimeout registry_tombstone=true hardware_tombstone=true retained_pages=3 generation=1")
            fail("malformed ResetTimeout receipt: " $0)
    } else if ($2 == "ResetAck") {
        require_event("ResetAck")
        if ($0 != "LINUX_FS_SAME_BOOT ResetAck generation=1->2 outcome=Completed retained_pages=3 generation_apply_atomic=true")
            fail("malformed ResetAck receipt: " $0)
    } else if ($2 == "IotlbTimeout") {
        require_event("IotlbTimeout")
        if ($0 != "LINUX_FS_SAME_BOOT IotlbTimeout registry_generation=2 hardware_identity_generation=1 retained_pages=3 registry_tombstone=true hardware_tombstone=true")
            fail("malformed IotlbTimeout receipt: " $0)
    } else if ($2 == "IotlbAck") {
        require_event("IotlbAck")
        if ($0 != "LINUX_FS_SAME_BOOT IotlbAck completed_pages=3 registry_generation=2 hardware_identity_generation=1 quiescence_applied=true")
            fail("malformed IotlbAck receipt: " $0)
    } else if ($2 == "Close") {
        require_event("Close")
        if ($0 != "LINUX_FS_SAME_BOOT Close leaf_first=dma_queue_owner_a,dma_queue_owner_b,dma_request_owner,block_request,filesystem_read,filesystem_syscall terminal_outcome=Completed guest_publication_pending=true")
            fail("malformed leaf-first Close receipt: " $0)
    } else if ($2 == "GuestPublication") {
        require_event("GuestPublication")
        if ($0 != "LINUX_FS_SAME_BOOT GuestPublication result=4 bytes=4 source=CompletedRequest registry_ack=true revoke_complete=true")
            fail("malformed guest-publication closure receipt: " $0)
    } else if ($2 == "PASS") {
        require_event("PASS")
        if ($0 != "LINUX_FS_SAME_BOOT PASS same_boot=true identity_preserving=true real_dma=true polling=true irq=false smp=1 scope=95 effects=6 credits=10 sector_sha256=4fb2b63ca7d483c6efaa756182133f05c7ef453fa82e94ce31826ebc4c104f66 image_sha256=9357413ed9a96a23af1750cc304265dd7dd1835eb58eb1fb50119cd80d0bc8ca sector_fnv1a=0x33913395b7798e6b")
            fail("malformed terminal same-boot result: " $0)
        pass_line = FNR
    } else {
        fail("unknown same-boot serial receipt: " $0)
    }
}

function validate_serial() {
    if (serial_validated || failed)
        return
    serial_validated = 1
    if (serial_events != 14)
        fail("expected 14 ordered same-boot receipts, observed " serial_events)
    if (owners != 3)
        fail("expected three exact DMA owner receipts, observed " owners)
    if (fixture_count != 1)
        fail("expected one immutable-fixture receipt, observed " fixture_count)
    if (spike_count != 1)
        fail("expected one feature-terminal SPIKE_RESULT PASS, observed " spike_count)
    if (!capture_line || !commit_line || !pass_line || !spike_line ||
        !(capture_line < commit_line && commit_line < pass_line &&
          pass_line < spike_line && spike_line < fixture_line))
        fail("capture/commit/PASS/SPIKE_RESULT/fixture order is incomplete or invalid")
}

function token_after(name,    i) {
    for (i = 1; i < NF; i++) {
        if ($i == name)
            return $(i + 1)
    }
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

function parse_debug_line(    vdev, req, queue, vq, iova, gpa) {
    sub(/\r$/, "")
    if ($0 ~ /^(LINUX_FS_SAME_BOOT|RUNTIME_FS_SAME_BOOT_FIXTURE)/)
        fail("guest serial receipt leaked into QEMU debug input: " $0)
    if ($0 ~ /virtio_blk_handle_write|blk_co_pwritev|vtd_dmar_fault|panicked at|Non-resettable panic!/)
        fail("forbidden QEMU/device trace: " $0)

    if ($1 == "virtio_set_status") {
        vdev = token_after("vdev")
        if (vdev !~ /^0x[0-9a-f]+$/ || $NF !~ /^[0-9]+$/)
            fail("malformed VirtIO status event: " $0)
        add_control("status:" $NF, vdev, "")
        return
    }
    if ($1 == "virtio_pci_notify_write") {
        add_control("notify", "", "")
        activity[++activities] = "notify"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_queue_notify") {
        vdev = token_after("vdev")
        queue = token_after("n")
        vq = token_after("vq")
        if (vdev !~ /^0x[0-9a-f]+$/ || queue != "0" || vq !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO queue notification: " $0)
        add_control("queue", vdev, "")
        activity[++activities] = "queue"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_blk_handle_read") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO read event: " $0)
        add_control($0 ~ / sector 0 nsectors 1$/ ? "read:sector0:1" : "read:other", vdev, req)
        activity[++activities] = "read"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_blk_rw_complete") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO backend completion: " $0)
        add_control($0 ~ / ret 0$/ ? "rw_complete:0" : "rw_complete:error", vdev, req)
        activity[++activities] = "rw_complete"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "virtio_blk_req_complete") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO request completion: " $0)
        add_control($0 ~ / status 0$/ ? "req_complete:0" : "req_complete:error", vdev, req)
        activity[++activities] = "req_complete"
        activity_line[activities] = FNR
        return
    }
    if ($1 == "vtd_inv_desc_iotlb_global") {
        add_control("iotlb_global", "", "")
        iotlb_globals++
        return
    }
    if ($1 == "vtd_inv_desc_wait_irq") {
        add_control("iotlb_wait", "", "")
        iotlb_waits++
        return
    }
    if ($1 == "vtd_dmar_translate") {
        activity[++activities] = "translate"
        activity_line[activities] = FNR
        iova = $5
        gpa = $8
        if (iova in owner_kind_by_iova) {
            if ($3 != "00:05.00" || gpa != owner_paddr[owner_kind_by_iova[iova]] || iova == gpa)
                fail("owned IOVA translated to the wrong BDF or paddr: " $0)
            seen_owner[owner_kind_by_iova[iova]] = 1
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
        fail("missing QEMU translation for the exact registry DMA owners")
    for (kind in owner_iova) {
        if (!(kind in seen_owner))
            fail("registry DMA owner was not translated by QEMU: " kind " " owner_iova[kind])
    }

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
    for (i = start; i <= target_end; i++) {
        if (control_vdev[i] != "" && control_vdev[i] != target_vdev)
            fail("target control sequence changed vdev at event " i)
    }
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
        if (activity_line[i] >= control_line[reset_position] && activity[i] == "translate")
            fail("DMA translation remained live after reset began")
    }
    for (i = target_end + 1; i <= controls; i++) {
        if (control[i] != "status:0" || control_vdev[i] != target_vdev)
            fail("unexpected control event after target quiescence: " control[i])
    }
}

BEGIN {
    image_sha = "9357413ed9a96a23af1750cc304265dd7dd1835eb58eb1fb50119cd80d0bc8ca"
    expected_event[1] = "Capture"
    expected_event[2] = "DmaOwner"
    expected_event[3] = "DmaOwner"
    expected_event[4] = "DmaOwner"
    expected_event[5] = "Commit"
    expected_event[6] = "Notify"
    expected_event[7] = "Completion"
    expected_event[8] = "ResetTimeout"
    expected_event[9] = "ResetAck"
    expected_event[10] = "IotlbTimeout"
    expected_event[11] = "IotlbAck"
    expected_event[12] = "Close"
    expected_event[13] = "GuestPublication"
    expected_event[14] = "PASS"
    expected_owner_kind[1] = "queue_driver"
    expected_owner_kind[2] = "queue_device"
    expected_owner_kind[3] = "request"
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
    # `./x check` uses mawk's dump mode as a parser-only syntax gate.
    if (NR == 0)
        exit 0
    if (failed)
        exit 1
    validate_serial()
    validate_debug()
}
