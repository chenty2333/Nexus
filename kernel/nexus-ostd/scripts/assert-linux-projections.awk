# Validate the compact, machine-readable Stage 6A personality receipts.
#
# The human-readable lines remain useful diagnostics, but this oracle treats a
# Projection as evidence only when it is paired with the immediately preceding
# PortalResult and when its complete identity tuple appears in the one allowed
# execution order below.  This makes missing, duplicated, or payload-swapped
# receipts fail closed.

function fail(message) {
    print "linux projection assertion failed at serial line " NR ": " message > "/dev/stderr"
    failed = 1
    exit 1
}

function add(namespace, action, sender, opcode, authority, scope, effect, task, operation, binding, result) {
    expected[++expected_count] = namespace \
        "|action=" action \
        "|sender=" sender \
        "|opcode=" opcode \
        "|authority_epoch=" authority \
        "|scope=" scope \
        "|effect=" effect \
        "|task=" task \
        "|operation=" operation \
        "|binding_epoch=" binding \
        "|result=" result
}

function must(sequence, field, expected_value) {
    required[sequence SUBSEP field] = expected_value
}

function link(sequence, previous_sequence) {
    chain_from[sequence] = previous_sequence
}

function core_key(    key, i) {
    key = $1
    for (i = 3; i <= 12; i++)
        key = key "|" $i
    return key
}

function result_key(    key, i) {
    key = $1
    for (i = 3; i <= 13; i++)
        key = key "|" $i
    return key
}

function parse_projection(    i, token, separator, name, actual_name) {
    if (NF != 35)
        fail("Projection has " NF " fields; expected 35")

    for (name in value)
        delete value[name]

    for (i = 3; i <= NF; i++) {
        token = $i
        separator = index(token, "=")
        if (separator == 0)
            fail("malformed Projection field: " token)
        actual_name = substr(token, 1, separator - 1)
        if (actual_name != field_order[i - 2])
            fail("Projection field " (i - 2) " is " actual_name "; expected " field_order[i - 2])
        if (actual_name in value)
            fail("duplicate Projection field: " actual_name)
        value[actual_name] = substr(token, separator + 1)
    }
}

function require_value(field, wanted, context) {
    if (value[field] != wanted)
        fail(context " has " field "=" value[field] "; expected " wanted)
}

BEGIN {
    field_order[1] = "action"
    field_order[2] = "sender"
    field_order[3] = "opcode"
    field_order[4] = "authority_epoch"
    field_order[5] = "scope"
    field_order[6] = "effect"
    field_order[7] = "task"
    field_order[8] = "operation"
    field_order[9] = "binding_epoch"
    field_order[10] = "result"
    field_order[11] = "mutation"
    field_order[12] = "scope_before"
    field_order[13] = "scope_after"
    field_order[14] = "recovery_before"
    field_order[15] = "recovery_after"
    field_order[16] = "write_before"
    field_order[17] = "write_after"
    field_order[18] = "exit_before"
    field_order[19] = "exit_after"
    field_order[20] = "delivery_before"
    field_order[21] = "delivery_after"
    field_order[22] = "prepared_before"
    field_order[23] = "prepared_after"
    field_order[24] = "queue_before"
    field_order[25] = "queue_after"
    field_order[26] = "wakers_before"
    field_order[27] = "wakers_after"
    field_order[28] = "live_before"
    field_order[29] = "live_after"
    field_order[30] = "guest_before"
    field_order[31] = "guest_after"
    field_order[32] = "closure_before"
    field_order[33] = "closure_after"

    unchanged_count = split("scope recovery write exit delivery prepared queue wakers live guest closure", unchanged, " ")

    # Main workload: stale/no-supervisor fencing, explicit adoption using the
    # old token, current-token identity/unknown-opcode rejection, and exactly
    # one terminal reply.  The two current-token probes deliberately follow
    # adoption so only the field under test differs from a usable token.
    add("LINUX_PORTAL", "post_crash", 401, "0x4c520002", 91, 30, 1, 400, 1, 1, "StaleBinding")
    add("LINUX_PORTAL", "pre_rebind", 403, "0x4c520002", 91, 30, 1, 400, 1, 2, "NoSupervisor")
    add("LINUX_PORTAL", "post_rebind", 403, "0x4c520002", 91, 30, 1, 400, 1, 1, "StaleBinding")
    add("LINUX_PORTAL", "Adopt", 403, "0x4c510005", 91, 30, 1, 400, 1, 1, "Applied")
    add("LINUX_PORTAL", "current", 403, "0x4c520002", 91, 30, 999, 400, 1, 2, "IdentityMismatch")
    add("LINUX_PORTAL", "Unknown", 403, "0x4c5f0001", 91, 30, 1, 400, 1, 2, "UnknownOperation")
    add("LINUX_PORTAL", "post_adopt", 403, "0x4c520002", 91, 30, 1, 400, 1, 1, "StaleBinding")
    add("LINUX_PORTAL", "Adopt", 403, "0x4c510005", 91, 30, 1, 400, 1, 2, "NotAdoptable")
    add("LINUX_PORTAL", "BackendCommit", 403, "0x4c520001", 91, 30, 1, 400, 1, 2, "AlreadyCommitted")
    add("LINUX_PORTAL", "current", 403, "0x4c520002", 91, 30, 1, 400, 1, 2, "Applied")
    add("LINUX_PORTAL", "current", 403, "0x4c520002", 91, 30, 1, 400, 1, 2, "AlreadyTerminal")

    # Scope 31: revoke wins before the backend commit and closure aborts.
    add("LINUX_REVOKE", "Prepare", 403, "0x4c530007", 91, 31, 5, 405, 1, 2, "Applied")
    add("LINUX_REVOKE", "RevokeBegin", 403, "0x4c530003", 91, 31, 5, 405, 1, 2, "Applied")
    add("LINUX_REVOKE", "RevokeComplete", 403, "0x4c530006", 91, 31, 5, 405, 1, 2, "NotQuiescent")
    add("LINUX_REVOKE", "BackendCommit", 403, "0x4c530002", 91, 31, 5, 405, 1, 2, "StaleAuthority")
    add("LINUX_REVOKE", "Reply", 403, "0x4c530004", 91, 31, 5, 405, 1, 2, "StaleAuthority")
    add("LINUX_REVOKE", "ClosureNext", 403, "0x4c530005", 91, 31, 5, 405, 1, 2, "Applied")
    add("LINUX_REVOKE", "RevokeComplete", 403, "0x4c530006", 91, 31, 5, 405, 1, 2, "Applied")

    # Scope 32: the backend commit wins, then closure drains without replay.
    add("LINUX_REVOKE", "Prepare", 403, "0x4c530007", 91, 32, 6, 406, 1, 2, "Applied")
    add("LINUX_REVOKE", "BackendCommit", 403, "0x4c530002", 91, 32, 6, 406, 1, 2, "Committed")
    add("LINUX_REVOKE", "RevokeBegin", 403, "0x4c530003", 91, 32, 6, 406, 1, 2, "Applied")
    add("LINUX_REVOKE", "RevokeComplete", 403, "0x4c530006", 91, 32, 6, 406, 1, 2, "NotQuiescent")
    add("LINUX_REVOKE", "BackendCommit", 403, "0x4c530002", 91, 32, 6, 406, 1, 2, "StaleAuthority")
    add("LINUX_REVOKE", "Reply", 403, "0x4c530004", 91, 32, 6, 406, 1, 2, "StaleAuthority")
    add("LINUX_REVOKE", "ClosureNext", 403, "0x4c530005", 91, 32, 6, 406, 1, 2, "Applied")
    add("LINUX_REVOKE", "RevokeComplete", 403, "0x4c530006", 91, 32, 6, 406, 1, 2, "Applied")

    # exit_group is a continuation too: early commit rejection, explicit
    # prepare, one commit that does not resume user mode, then duplicate reject.
    add("LINUX_PORTAL", "CommitExit", 403, "0x4c510008", 91, 30, 2, 400, 2, 2, "InvalidState")
    add("LINUX_PORTAL", "PrepareExit", 403, "0x4c510009", 91, 30, 2, 400, 2, 2, "Applied")
    add("LINUX_PORTAL", "CommitExit", 403, "0x4c510008", 91, 30, 2, 400, 2, 2, "Applied")
    add("LINUX_PORTAL", "CommitExit", 403, "0x4c510008", 91, 30, 2, 400, 2, 2, "AlreadyTerminal")

    # These ranges have no out-of-band semantic mutation between portal
    # operations.  Preserve the complete after -> before chain, not only each
    # operation's local transition.
    link(4, 3)
    link(5, 4)
    link(6, 5)
    link(7, 6)
    link(8, 7)
    link(9, 8)
    link(10, 9)
    link(13, 12)
    link(14, 13)
    link(15, 14)
    link(16, 15)
    link(17, 16)
    link(18, 17)
    link(20, 19)
    link(21, 20)
    link(22, 21)
    link(23, 22)
    link(24, 23)
    link(25, 24)
    link(26, 25)
    link(28, 27)
    link(29, 28)

    # Positive transition anchors.  Rejected transitions are checked
    # generically below by comparing every semantic before/after component.
    must(1, "scope_before", "Active:91:2:None")
    must(1, "recovery_before", "true:false:false")
    must(1, "write_before", "91:30:1:400:1:1:Some(BackendCommitted)")
    must(2, "scope_before", "Active:91:2:None")
    must(2, "recovery_before", "true:true:true")
    must(2, "write_before", "91:30:1:400:1:1:Some(BackendCommitted)")
    must(3, "scope_before", "Active:91:2:Some(403)")
    must(3, "recovery_before", "false:true:true")
    must(3, "write_before", "91:30:1:400:1:1:Some(BackendCommitted)")
    must(4, "write_before", "91:30:1:400:1:1:Some(BackendCommitted)")
    must(4, "write_after",  "91:30:1:400:1:2:Some(BackendCommitted)")
    must(5, "scope_before", "Active:91:2:Some(403)")
    must(5, "write_before", "91:30:1:400:1:2:Some(BackendCommitted)")
    must(6, "scope_before", "Active:91:2:Some(403)")
    must(6, "write_before", "91:30:1:400:1:2:Some(BackendCommitted)")
    must(7, "write_before", "91:30:1:400:1:2:Some(BackendCommitted)")
    must(8, "write_before", "91:30:1:400:1:2:Some(BackendCommitted)")
    must(9, "write_before", "91:30:1:400:1:2:Some(BackendCommitted)")

    must(10, "write_before", "91:30:1:400:1:2:Some(BackendCommitted)")
    must(10, "write_after",  "91:30:1:400:1:2:Some(Completed)")
    must(10, "delivery_before", "1:0:0:0:0:0:1")
    must(10, "delivery_after",  "1:1:1:0:0:1:1")
    must(10, "wakers_before", "true:false:true:2")
    must(10, "wakers_after",  "false:false:true:1")
    must(10, "live_before", "1")
    must(10, "live_after",  "0")
    must(11, "write_before", "91:30:1:400:1:2:Some(Completed)")

    must(12, "write_before", "91:31:5:405:1:2:Some(Captured)")
    must(12, "write_after",  "91:31:5:405:1:2:Some(ReplyPrepared)")
    must(12, "prepared_before", "false:0:0x0")
    must(12, "prepared_after",  "true:0:0xcbf29ce484222325")
    must(13, "scope_before", "Active:91:2:Some(403)")
    must(13, "scope_after",  "Closing:92:2:None")
    must(13, "closure_before", "0:0:0:0")
    must(13, "closure_after",  "1:0:0:0")
    must(14, "scope_before", "Closing:92:2:None")
    must(14, "live_before", "1")
    must(14, "live_after",  "1")
    must(14, "closure_before", "1:0:0:0")
    must(14, "closure_after",  "1:0:0:0")
    must(15, "write_before", "91:31:5:405:1:2:Some(ReplyPrepared)")
    must(16, "write_before", "91:31:5:405:1:2:Some(ReplyPrepared)")
    must(17, "write_before", "91:31:5:405:1:2:Some(ReplyPrepared)")
    must(17, "write_after",  "91:31:5:405:1:2:Some(Aborted)")
    must(17, "delivery_before", "0:0:0:0:0:0:0")
    must(17, "delivery_after",  "0:0:0:0:1:1:0")
    must(17, "prepared_before", "true:0:0xcbf29ce484222325")
    must(17, "prepared_after",  "false:0:0x0")
    must(17, "wakers_before", "true:false:false:1")
    must(17, "wakers_after",  "false:false:false:0")
    must(17, "live_before", "1")
    must(17, "live_after",  "0")
    must(17, "closure_before", "1:0:0:0")
    must(17, "closure_after",  "1:1:1:1")
    must(18, "scope_before", "Closing:92:2:None")
    must(18, "scope_after",  "Revoked:92:2:None")
    must(18, "write_after", "91:31:5:405:1:2:Some(Aborted)")
    must(18, "live_after", "0")
    must(18, "closure_after", "1:1:1:1")

    must(19, "write_before", "91:32:6:406:1:2:Some(Captured)")
    must(19, "write_after",  "91:32:6:406:1:2:Some(ReplyPrepared)")
    must(19, "prepared_before", "false:0:0x0")
    must(19, "prepared_after",  "true:0:0xcbf29ce484222325")
    must(20, "write_before", "91:32:6:406:1:2:Some(ReplyPrepared)")
    must(20, "write_after",  "91:32:6:406:1:2:Some(BackendCommitted)")
    must(20, "delivery_before", "0:0:0:0:0:0:0")
    must(20, "delivery_after",  "1:0:0:0:0:0:1")
    must(20, "prepared_before", "true:0:0xcbf29ce484222325")
    must(20, "prepared_after",  "false:0:0x0")
    must(21, "scope_before", "Active:91:2:Some(403)")
    must(21, "scope_after",  "Closing:92:2:None")
    must(21, "closure_before", "0:0:0:0")
    must(21, "closure_after",  "1:0:0:0")
    must(22, "scope_before", "Closing:92:2:None")
    must(22, "live_before", "1")
    must(22, "live_after",  "1")
    must(22, "closure_before", "1:0:0:0")
    must(22, "closure_after",  "1:0:0:0")
    must(23, "write_before", "91:32:6:406:1:2:Some(BackendCommitted)")
    must(24, "write_before", "91:32:6:406:1:2:Some(BackendCommitted)")
    must(25, "write_before", "91:32:6:406:1:2:Some(BackendCommitted)")
    must(25, "write_after",  "91:32:6:406:1:2:Some(Completed)")
    must(25, "delivery_before", "1:0:0:0:0:0:1")
    must(25, "delivery_after",  "1:1:1:0:0:1:1")
    must(25, "wakers_before", "true:false:false:1")
    must(25, "wakers_after",  "false:false:false:0")
    must(25, "live_before", "1")
    must(25, "live_after",  "0")
    must(25, "closure_before", "1:0:0:0")
    must(25, "closure_after",  "1:1:1:1")
    must(26, "scope_before", "Closing:92:2:None")
    must(26, "scope_after",  "Revoked:92:2:None")
    must(26, "write_after", "91:32:6:406:1:2:Some(Completed)")
    must(26, "live_after", "0")
    must(26, "closure_after", "1:1:1:1")

    must(28, "exit_before", "91:30:2:400:2:2:Some(Captured)")
    must(28, "exit_after",  "91:30:2:400:2:2:Some(ReplyPrepared)")
    must(27, "exit_before", "91:30:2:400:2:2:Some(Captured)")
    must(27, "live_before", "1")
    must(27, "guest_before", "Running:false")
    must(29, "exit_before", "91:30:2:400:2:2:Some(ReplyPrepared)")
    must(29, "exit_after",  "91:30:2:400:2:2:Some(Completed)")
    must(29, "delivery_before", "1:1:1:0:0:1:1")
    must(29, "delivery_after",  "1:2:1:1:0:2:1")
    must(29, "wakers_before", "false:true:true:2")
    must(29, "wakers_after",  "false:false:true:1")
    must(29, "live_before", "1")
    must(29, "live_after",  "0")
    must(29, "guest_before", "Running:false")
    must(29, "guest_after",  "Exited(0):false")
    must(30, "guest_before", "Exited(0):true")
    must(30, "guest_after",  "Exited(0):true")
}

{
    sub(/\r$/, "")
}

($1 == "LINUX_PORTAL" || $1 == "LINUX_REVOKE") && $2 == "PortalResult" {
    if (NF < 13)
        fail("truncated PortalResult")
    portal_result_count++
    last_result_line = NR
    last_result = result_key()
    next
}

($1 == "LINUX_PORTAL" || $1 == "LINUX_REVOKE") && $2 == "Projection" {
    projection_count++
    parse_projection()

    if (projection_count > expected_count)
        fail("unexpected extra Projection: " core_key())
    if (core_key() != expected[projection_count])
        fail("Projection " projection_count " identity/order mismatch; got " core_key() "; expected " expected[projection_count])
    if (last_result_line != NR - 1)
        fail("Projection is not immediately paired with its PortalResult")
    if (result_key() != last_result)
        fail("Projection identity/result differs from its PortalResult")

    if (projection_count in chain_from) {
        previous_projection = chain_from[projection_count]
        for (i = 1; i <= unchanged_count; i++) {
            component = unchanged[i]
            if (value[component "_before"] != projection_after[previous_projection SUBSEP component])
                fail("Projection " projection_count " breaks the semantic chain for " component ": previous after=" projection_after[previous_projection SUBSEP component] ", current before=" value[component "_before"])
        }
    }

    successful = (value["result"] == "Applied" || value["result"] == "Committed")
    if (successful) {
        if (value["mutation"] != "true")
            fail("successful " value["action"] " must report mutation=true")
        changed = 0
        for (i = 1; i <= unchanged_count; i++) {
            component = unchanged[i]
            if (value[component "_before"] != value[component "_after"])
                changed = 1
        }
        if (!changed)
            fail("successful " value["action"] " has no semantic state change")
    } else {
        if (value["mutation"] != "false")
            fail("rejected " value["action"] " must report mutation=false")
        for (i = 1; i <= unchanged_count; i++) {
            component = unchanged[i]
            if (value[component "_before"] != value[component "_after"])
                fail("rejected " value["action"] " changed " component ": " value[component "_before"] " -> " value[component "_after"])
        }
    }

    for (requirement in required) {
        split(requirement, requirement_parts, SUBSEP)
        if (requirement_parts[1] == projection_count)
            require_value(requirement_parts[2], required[requirement], "Projection " projection_count)
    }

    for (i = 1; i <= unchanged_count; i++) {
        component = unchanged[i]
        projection_after[projection_count SUBSEP component] = value[component "_after"]
    }

    projection_line[projection_count] = NR
    next
}

$1 == "LINUX_REVOKE" && $2 == "PASS" {
    revoke_pass_count++
    if ($0 == "LINUX_REVOKE PASS parent_scope=30 scope=31 authority_epoch=92 target_count=1 steps=1 final=Aborted backend_commits=0 replies=0 resumes=0 aborts=1 post_revoke_exclusion=true quiescent=true") {
        if (pass31_line != 0)
            fail("duplicate scope-31 PASS receipt")
        pass31_line = NR
    } else if ($0 == "LINUX_REVOKE PASS parent_scope=30 scope=32 authority_epoch=92 target_count=1 steps=1 final=Completed backend_commits=1 replies=1 resumes=1 aborts=0 post_revoke_exclusion=true quiescent=true") {
        if (pass32_line != 0)
            fail("duplicate scope-32 PASS receipt")
        pass32_line = NR
    } else {
        fail("unexpected LINUX_REVOKE PASS receipt: " $0)
    }
    next
}

$0 == "LINUX_SLICE PASS workload=linux-hello write=true exit_group=true personality_crash_rebind=true stale_reply_fenced=true terminalizations=2 output_publications=1" {
    linux_slice_pass_count++
    linux_slice_pass_line = NR
}

$0 == "SPIKE_RESULT PASS" {
    prototype_pass_count++
    prototype_pass_line = NR
}

END {
    if (failed)
        exit 1
    if (projection_count != expected_count) {
        print "linux projection assertion failed: expected " expected_count " Projections, observed " (projection_count + 0) > "/dev/stderr"
        exit 1
    }
    if (portal_result_count != expected_count) {
        print "linux projection assertion failed: expected " expected_count " PortalResults, observed " (portal_result_count + 0) > "/dev/stderr"
        exit 1
    }
    if (revoke_pass_count != 2 || pass31_line == 0 || pass32_line == 0) {
        print "linux projection assertion failed: missing or extra scoped revoke PASS receipts" > "/dev/stderr"
        exit 1
    }
    if (linux_slice_pass_count != 1 || prototype_pass_count != 1) {
        print "linux projection assertion failed: missing or duplicate final PASS receipt" > "/dev/stderr"
        exit 1
    }
    if (!(projection_line[18] < projection_line[26] && \
          projection_line[26] < pass31_line && \
          pass31_line < pass32_line && \
          pass32_line < linux_slice_pass_line && \
          linux_slice_pass_line < prototype_pass_line)) {
        print "linux projection assertion failed: revoke closure/PASS receipts are out of order" > "/dev/stderr"
        exit 1
    }
}
