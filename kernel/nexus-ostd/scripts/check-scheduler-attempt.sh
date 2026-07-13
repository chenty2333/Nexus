#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
source_file=${1:-"$root/src/domains/scheduler.rs"}
gate_source=${2:-"$root/../../crates/cser-transition-gates/src/scheduler.rs"}

awk '
    index($0, "let next = self.runnable.pop_front()?;") {
        pop_count++
        pop_line = NR
    }
    index($0, ".note_fallback_pick(") {
        gate_count++
        gate_line = NR
    }
    index($0, "\"CSER FallbackPick authority_epoch=") {
        receipt_count++
        receipt_line = NR
    }
    /^[[:space:]]*(fallback_selection_attempts|fallback_pick_tick|fallback_pick_task_id|fallback_pick_selection_attempt):/ {
        shadow_count++
    }
    END {
        if (pop_count != 1 || gate_count != 1 || receipt_count != 1) {
            print "scheduler attempt source gate: expected one pop/gate-pick/receipt" > "/dev/stderr"
            exit 1
        }
        if (!(pop_line < gate_line && gate_line < receipt_line)) {
            print "scheduler attempt source gate: gate ordinal advances before successful pop or receipt precedes gate" > "/dev/stderr"
            exit 1
        }
        if (shadow_count != 0) {
            print "scheduler attempt source gate: shadow fallback evidence fields remain in production adapter" > "/dev/stderr"
            exit 1
        }
        print "scheduler attempt source gate: PASS pop_before_gate_pick=true receipt_after_gate=true shadow_fallback_fields=false"
    }
' "$source_file"

awk '
    /^[[:space:]]*fn propose_inner\(/ {
        in_propose = 1
    }
    in_propose && /^[[:space:]]*pub fn crash\(/ {
        in_propose = 0
    }
    in_propose && index($0, "let known_task = queue.contains_task(task_id);") {
        known_count++
        known_line = NR
    }
    in_propose && index($0, "let receipt = match queue.gate.prepare(") {
        prepare_count++
        prepare_line = NR
    }
    in_propose && index($0, "Ok(receipt) => receipt") {
        receipt_count++
        receipt_line = NR
    }
    /^struct CserRunQueue \{/ {
        in_queue = 1
    }
    in_queue && /^}/ {
        in_queue = 0
    }
    in_queue && index($0, "gate: SchedulerGate<Proposal>") {
        owned_gate_count++
    }
    in_queue && /^[[:space:]]*(binding|pending|mode|tick|lease_ticks|lease_deadline_tick|crash_tick|fallback_[a-z_]+):/ {
        shadow_count++
    }
    END {
        if (known_count != 1 || prepare_count != 1 || receipt_count != 1 || owned_gate_count != 1) {
            print "scheduler adapter source gate: expected one known-task input, gate prepare, accepted receipt, and owned SchedulerGate" > "/dev/stderr"
            exit 1
        }
        if (!(known_line < prepare_line && prepare_line < receipt_line)) {
            print "scheduler adapter source gate: accepted receipt escaped gate.prepare ordering" > "/dev/stderr"
            exit 1
        }
        if (shadow_count != 0) {
            print "scheduler adapter source gate: shadow binding/mode/pending/lease/fallback fields remain" > "/dev/stderr"
            exit 1
        }
        print "scheduler adapter source gate: PASS gate_owned=true known_task_before_prepare=true receipt_from_gate=true shadow_recovery_fields=false"
    }
' "$source_file"

awk '
    /^[[:space:]]*pub fn prepare\(/ {
        in_prepare = 1
    }
    in_prepare && /^[[:space:]]*pub fn take_bound_proposal\(/ {
        in_prepare = 0
    }
    in_prepare && index($0, "if presented != self.binding") {
        stale_count++
        stale_line = NR
    }
    in_prepare && index($0, "if self.mode != SchedulerMode::Bound") {
        supervisor_count++
        supervisor_line = NR
    }
    in_prepare && index($0, "if !known_task") {
        task_count++
        task_line = NR
    }
    in_prepare && index($0, "let lease_deadline_tick = self") {
        deadline_count++
        deadline_line = NR
    }
    in_prepare && index($0, "let receipt = PreparedProposal {") {
        build_count++
        build_line = NR
    }
    in_prepare && index($0, "self.pending = Some(proposal);") {
        pending_count++
        pending_line = NR
    }
    in_prepare && index($0, "self.lease_deadline_tick = lease_deadline_tick;") {
        lease_count++
        lease_line = NR
    }
    in_prepare && index($0, "Ok(receipt)") {
        return_count++
        return_line = NR
    }
    END {
        if (stale_count != 1 || supervisor_count != 1 || task_count != 1 ||
            deadline_count != 1 || build_count != 1 || pending_count != 1 ||
            lease_count != 1 || return_count != 1) {
            print "scheduler transition gate: expected three reject gates and one checked deadline/receipt/pending/lease/return" > "/dev/stderr"
            exit 1
        }
        if (!(stale_line < supervisor_line && supervisor_line < task_line &&
              task_line < deadline_line && deadline_line < build_line &&
              build_line < pending_line && pending_line < lease_line &&
              lease_line < return_line)) {
            print "scheduler transition gate: rejection, failure-atomic calculation, or receipt publication ordering changed" > "/dev/stderr"
            exit 1
        }
        print "scheduler transition gate: PASS rejected_proposals_do_not_mutate=true checked_deadline_before_mutation=true receipt_after_pending_and_lease=true"
    }
' "$gate_source"
