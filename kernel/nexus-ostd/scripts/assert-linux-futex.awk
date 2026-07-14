# Validate the Stage 6B.1 futex personality portal receipts.
#
# A Projection is evidence only when it follows the preceding unmatched
# PortalResult, agrees with its scenario/action/result/mutation tuple, and
# occurs in the one allowed bounded trace. Scheduler diagnostics may interleave
# after the futex lock is released, so physical adjacency is not required.
# Projection values for wait/wake tokens contain spaces, so the semantic state
# is parsed between ordered field labels rather than with AWK whitespace fields.

function fail(message) {
    print "linux futex projection assertion failed at serial line " NR ": " message > "/dev/stderr"
    failed = 1
    exit 1
}

function expect(scenario, action, result, mutation) {
    expected[++expected_count] = scenario "|" action "|" result "|" mutation
}

function simple_value(position, name,    prefix, token) {
    prefix = name "="
    token = $position
    if (index(token, prefix) != 1)
        fail("field " position " is " token "; expected " prefix "...")
    return substr(token, length(prefix) + 1)
}

function state_value(line, name, next_name,    marker, next_marker, start, finish) {
    marker = " " name "="
    start = index(line, marker)
    if (start == 0)
        fail("Projection is missing " name)
    start += length(marker)

    if (next_name == "")
        return substr(line, start)

    next_marker = " " next_name "="
    finish = index(line, next_marker)
    if (finish == 0 || finish <= start)
        fail("Projection fields are missing or out of order at " name)
    return substr(line, start, finish - start)
}

function parse_projection(line,    i, name, next_name, prefix) {
    projection_scenario = simple_value(3, "scenario")
    projection_action = simple_value(4, "action")
    projection_result = simple_value(5, "result")
    projection_mutation = simple_value(6, "mutation")

    prefix = "LINUX_FUTEX Projection" \
        " scenario=" projection_scenario \
        " action=" projection_action \
        " result=" projection_result \
        " mutation=" projection_mutation
    if (index(line, prefix " scope_before=") != 1)
        fail("Projection has unexpected fields before scope_before")

    for (i = 1; i <= state_count; i++) {
        name = state_order[i]
        next_name = i < state_count ? state_order[i + 1] : ""
        state[name] = state_value(line, name, next_name)
        if (state[name] == "")
            fail("Projection has an empty " name)
    }

    if (state["publications_before"] !~ /^[0-9]+:[0-9]+$/ ||
        state["publications_after"] !~ /^[0-9]+:[0-9]+$/)
        fail("Projection has malformed publication counters")
}

BEGIN {
    portal_names[1] = "scenario"
    portal_names[2] = "action"
    portal_names[3] = "sender"
    portal_names[4] = "opcode"
    portal_names[5] = "authority_epoch"
    portal_names[6] = "scope"
    portal_names[7] = "effect"
    portal_names[8] = "task"
    portal_names[9] = "operation"
    portal_names[10] = "address_space"
    portal_names[11] = "generation"
    portal_names[12] = "address"
    portal_names[13] = "binding_epoch"
    portal_names[14] = "result"
    portal_names[15] = "mutation"

    pair_count = split("scope recovery wait wake queue frozen credits watchdog wakers pending live blocked terminal publications", pairs, " ")
    for (i = 1; i <= pair_count; i++) {
        state_order[++state_count] = pairs[i] "_before"
        state_order[++state_count] = pairs[i] "_after"
    }

    expect("recover", "RecvWait", "Applied", "false")
    expect("recover", "WaitRegister", "Applied", "true")
    expect("recover", "Snapshot", "Applied", "true")
    expect("recover", "Ready", "Applied", "true")
    expect("recover", "WaitRegister", "NoSupervisor", "false")
    expect("recover", "Rebind", "Applied", "true")
    expect("recover", "WaitRegister", "StaleBinding", "false")
    expect("recover", "RecoverNext", "Applied", "false")
    expect("recover", "Adopt", "Applied", "true")
    expect("recover", "Adopt", "IdentityMismatch", "false")
    expect("recover", "WaitRegister", "StaleBinding", "false")
    expect("recover", "Adopt", "NotAdoptable", "false")
    expect("recover", "EnableWaker", "Applied", "true")
    expect("recover", "RecvWake", "Applied", "false")
    expect("recover", "WakeCommit", "Applied", "true")
    expect("recover", "WakeCommit", "InvalidState", "false")
    expect("recover", "WakeCommit", "StaleAuthority", "false")
    expect("expire", "RecvWait", "Applied", "false")
    expect("expire", "WaitRegister", "Applied", "true")
    expect("expire", "EnableWaker", "Applied", "true")
    expect("expire", "RecvWake", "Applied", "false")
    expect("expire", "WakeCommit", "StaleAuthority", "false")

    expected_rejects["NoSupervisor"] = 1
    expected_rejects["StaleBinding"] = 2
    expected_rejects["IdentityMismatch"] = 1
    expected_rejects["NotAdoptable"] = 1
    expected_rejects["InvalidState"] = 1
    expected_rejects["StaleAuthority"] = 2
}

{
    sub(/\r$/, "")
    is_portal = $0 ~ /^LINUX_FUTEX PortalResult /
    is_projection = $0 ~ /^LINUX_FUTEX Projection /

    if (is_portal && pending)
        fail("PortalResult at line " pending_line " has no paired Projection")
    if (is_projection && !pending)
        fail("orphan Projection")
}

/^LINUX_FUTEX PortalResult / {
    if (NF != 17)
        fail("PortalResult has " NF " fields; expected 17")
    for (i = 1; i <= 15; i++)
        simple_value(i + 2, portal_names[i])

    portal_scenario = simple_value(3, "scenario")
    portal_action = simple_value(4, "action")
    portal_result = simple_value(16, "result")
    portal_mutation = simple_value(17, "mutation")
    portal_tuple = portal_scenario "|" portal_action "|" portal_result "|" portal_mutation

    portal_count++
    if (portal_count > expected_count || portal_tuple != expected[portal_count])
        fail("unexpected PortalResult #" portal_count ": " portal_tuple)

    if (portal_result != "Applied") {
        if (portal_mutation != "false")
            fail("rejected PortalResult reports mutation=true")
        reject_count[portal_result]++
    }

    pending = 1
    pending_line = NR
    next
}

/^LINUX_FUTEX Projection / {
    parse_projection($0)
    projection_count++

    if (projection_scenario != portal_scenario ||
        projection_action != portal_action ||
        projection_result != portal_result ||
        projection_mutation != portal_mutation)
        fail("Projection tuple does not match PortalResult at line " pending_line)

    # mutation=false is stronger than merely reporting a rejected result: the
    # complete compressed semantic state must remain unchanged.
    if (projection_mutation == "false") {
        for (i = 1; i <= pair_count; i++) {
            before_name = pairs[i] "_before"
            after_name = pairs[i] "_after"
            if (state[before_name] != state[after_name])
                fail(portal_result " changed " pairs[i] " despite mutation=false")
        }
    }

    pending = 0
    pending_line = 0
    next
}

END {
    if (failed)
        exit 1
    if (pending)
        fail("PortalResult at line " pending_line " has no Projection")
    if (portal_count != expected_count || projection_count != expected_count)
        fail("expected " expected_count " PortalResult/Projection pairs, observed " portal_count "/" projection_count)

    for (result in expected_rejects) {
        if (reject_count[result] != expected_rejects[result])
            fail("reject count for " result " is " reject_count[result] "; expected " expected_rejects[result])
    }
}
