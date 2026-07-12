# SPDX-License-Identifier: MPL-2.0

function fail(message) {
    print "Stage 5B debug-trace assertion failed: " message > "/dev/stderr"
    failed = 1
    exit 1
}

function field(name,    i, prefix) {
    prefix = name "="
    for (i = 1; i <= NF; i++) {
        if (index($i, prefix) == 1)
            return substr($i, length(prefix) + 1)
    }
    return ""
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

function expect(position, value) {
    expected[++expected_count] = value
    expected_index[expected_count] = position
}

NR == FNR {
    sub(/\r$/, "")
    if ($0 ~ /^DMA Owner generation=1 kind=/) {
        if ($0 !~ /^DMA Owner generation=1 kind=(queue_driver|queue_device|request) paddr=0x[0-9a-f]+ iova=0x[0-9a-f]+ remapped=true$/)
            fail("guest DMA owner has an unexpected field or shape: " $0)
        kind = field("kind")
        paddr = field("paddr")
        iova = field("iova")
        if (kind !~ /^(queue_driver|queue_device|request)$/ ||
            paddr !~ /^0x[0-9a-f]+$/ || iova !~ /^0x[0-9a-f]+$/ ||
            field("remapped") != "true" || paddr == iova)
            fail("malformed or identity-mapped guest DMA owner: " $0)
        if (kind in owner_iova || iova in owner_paddr || paddr in owner_kind_by_paddr)
            fail("duplicate guest DMA owner identity: " $0)
        owner_iova[kind] = iova
        owner_paddr[iova] = paddr
        owner_kind_by_paddr[paddr] = kind
        owners++
    }
    next
}

{
    sub(/\r$/, "")

    if ($0 ~ /^(VIRTIO_CSER|PCI Found|DMA Owner|DMA Owners|IO |RESET |REVOKE |REBIND |DEVICE |IOTLB |COMPLETION |FIXTURE Hash)/)
        fail("guest serial receipt leaked into QEMU debug input: " $0)
    if ($0 ~ /virtio_blk_handle_write/ || $0 ~ /blk_co_pwritev/ ||
        $0 ~ /vtd_dmar_fault/ || $0 ~ /panicked at/ ||
        $0 ~ /Non-resettable panic!/)
        fail("forbidden device trace: " $0)

    if ($1 == "virtio_set_status") {
        vdev = token_after("vdev")
        if (vdev !~ /^0x[0-9a-f]+$/ || $NF !~ /^[0-9]+$/)
            fail("malformed VirtIO status event: " $0)
        add_control("status:" $NF, vdev, "")
        next
    }
    if ($1 == "virtio_pci_notify_write") {
        add_control("notify", "", "")
        activity[++activities] = "notify"
        activity_line[activities] = FNR
        next
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
        next
    }
    if ($1 == "virtio_blk_handle_read") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO read event: " $0)
        if ($0 ~ / sector 0 nsectors 1$/)
            add_control("read:sector0:1", vdev, req)
        else
            add_control("read:other", vdev, req)
        activity[++activities] = "read"
        activity_line[activities] = FNR
        next
    }
    if ($1 == "virtio_blk_rw_complete") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO backend completion: " $0)
        add_control($0 ~ / ret 0$/ ? "rw_complete:0" : "rw_complete:error", vdev, req)
        activity[++activities] = "rw_complete"
        activity_line[activities] = FNR
        next
    }
    if ($1 == "virtio_blk_req_complete") {
        vdev = token_after("vdev")
        req = token_after("req")
        if (vdev !~ /^0x[0-9a-f]+$/ || req !~ /^0x[0-9a-f]+$/)
            fail("malformed VirtIO request completion: " $0)
        add_control($0 ~ / status 0$/ ? "req_complete:0" : "req_complete:error", vdev, req)
        activity[++activities] = "req_complete"
        activity_line[activities] = FNR
        next
    }
    if ($1 == "vtd_inv_desc_iotlb_global") {
        add_control("iotlb_global", "", "")
        iotlb_globals++
        next
    }
    if ($1 == "vtd_inv_desc_wait_irq") {
        add_control("iotlb_wait", "", "")
        iotlb_waits++
        next
    }
    if ($1 == "vtd_dmar_translate") {
        activity[++activities] = "translate"
        activity_line[activities] = FNR
        iova = $5
        gpa = $8
        if (iova in owner_paddr) {
            if ($3 != "00:05.00" || gpa != owner_paddr[iova] || iova == gpa)
                fail("owned IOVA translated to the wrong device or paddr: " $0)
            seen_iova[iova] = 1
            if (!first_owned_line) {
                first_owned_line = FNR
                controls_before_first_owned = controls
            }
            last_owned_line = FNR
        }
        next
    }
}

END {
    if (failed)
        exit 1
    if (owners != 3)
        fail("expected three exact guest DMA owners, observed " owners)
    for (kind in owner_iova) {
        if (!(owner_iova[kind] in seen_iova))
            fail("owned IOVA was not translated by QEMU: " owner_iova[kind])
    }
    if (!first_owned_line)
        fail("missing owned-I/O translation anchor")

    # At the first owned translation, the target phase must already have
    # published the exact initialization and one notify pair. Firmware events
    # before this suffix are intentionally outside the oracle.
    start = controls_before_first_owned - 6
    if (start < 1)
        fail("owned-I/O anchor has no complete initialization prefix")

    expect(start + 0, "status:0")
    expect(start + 1, "status:0")
    expect(start + 2, "status:3")
    expect(start + 3, "status:11")
    expect(start + 4, "status:15")
    expect(start + 5, "notify")
    expect(start + 6, "queue")
    expect(start + 7, "read:sector0:1")
    expect(start + 8, "rw_complete:0")
    expect(start + 9, "req_complete:0")

    # Generation 1 reset/retry: five real status=0 writes, then one global
    # invalidation and wait acknowledgement per retained DMA owner.
    for (i = 10; i <= 14; i++)
        expect(start + i, "status:0")
    for (i = 0; i < 3; i++) {
        expect(start + 15 + i * 2, "iotlb_global")
        expect(start + 16 + i * 2, "iotlb_wait")
    }

    # Fresh generation 2 initialization followed by the second whole-device
    # reset and its independent three-owner invalidation acknowledgement.
    expect(start + 21, "status:0")
    expect(start + 22, "status:0")
    expect(start + 23, "status:3")
    expect(start + 24, "status:11")
    expect(start + 25, "status:15")
    for (i = 26; i <= 30; i++)
        expect(start + i, "status:0")
    for (i = 0; i < 3; i++) {
        expect(start + 31 + i * 2, "iotlb_global")
        expect(start + 32 + i * 2, "iotlb_wait")
    }

    for (i = 1; i <= expected_count; i++) {
        position = expected_index[i]
        if (control[position] != expected[i])
            fail("target control event " position " mismatch; expected " expected[i] \
                 ", observed " control[position])
    }

    # Every target event that carries a device identity must refer to the same
    # VirtIO block device. The three completion records must additionally carry
    # one request identity; otherwise unrelated QEMU events could be spliced
    # into a syntactically valid control sequence.
    target_vdev = control_vdev[start]
    target_req = control_req[start + 7]
    if (target_vdev !~ /^0x[0-9a-f]+$/ || target_req !~ /^0x[0-9a-f]+$/)
        fail("target request has no valid vdev/req identity")
    for (i = start; i <= start + 4; i++) {
        if (control_vdev[i] != target_vdev)
            fail("target initialization changed vdev at control event " i)
    }
    for (i = start + 6; i <= start + 14; i++) {
        if (control_vdev[i] != target_vdev)
            fail("target request/reset changed vdev at control event " i)
    }
    for (i = start + 21; i <= start + 30; i++) {
        if (control_vdev[i] != target_vdev)
            fail("target rebind/reset changed vdev at control event " i)
    }
    for (i = start + 7; i <= start + 9; i++) {
        if (control_req[i] != target_req)
            fail("target read/completion changed req at control event " i)
    }

    request_end_line = control_line[start + 9]
    first_reset_line = control_line[start + 10]
    target_end_line = control_line[start + 36]
    if (first_owned_line <= control_line[start + 6] ||
        last_owned_line >= first_reset_line)
        fail("owned translations escaped the request-1 publish/completion window")
    if (iotlb_globals != 6 || iotlb_waits != 6)
        fail("expected two exact three-owner IOTLB completion chains")

    for (i = 1; i <= activities; i++) {
        if (activity_line[i] > target_end_line)
            fail("device activity after the second IOTLB acknowledgement: " activity[i])
        if (activity_line[i] >= first_reset_line && activity[i] == "translate")
            fail("DMA translation remained live after request-1 reset began")
    }

    # QEMU may publish one final status=0 while tearing down the already
    # quiescent device. No other control event may follow the target proof.
    for (i = start + 37; i <= controls; i++) {
        if (control[i] != "status:0" || control_vdev[i] != target_vdev)
            fail("unexpected control event after target quiescence: " control[i])
    }
}
