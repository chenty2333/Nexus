#!/usr/bin/env bash
set -euo pipefail

source_file=${1:-src/domains/scheduler.rs}

awk '
    index($0, "let next = self.runnable.pop_front()?;") {
        pop_count++
        pop_line = NR
    }
    index($0, "self.fallback_selection_attempts = self") {
        increment_count++
        increment_line = NR
    }
    index($0, "let selection_attempt = self.fallback_selection_attempts;") {
        capture_count++
        capture_line = NR
    }
    END {
        if (pop_count != 1 || increment_count != 1 || capture_count != 1) {
            print "scheduler attempt source gate: expected one pop/increment/capture" > "/dev/stderr"
            exit 1
        }
        if (!(pop_line < increment_line && increment_line < capture_line)) {
            print "scheduler attempt source gate: diagnostic ordinal advances before successful pop" > "/dev/stderr"
            exit 1
        }
        print "scheduler attempt source gate: PASS pop_before_increment=true hidden_ordinal_gaps=false diagnostics_only=true"
    }
' "$source_file"

awk '
    /^[[:space:]]*fn propose_inner\(/ {
        in_propose = 1
    }
    in_propose && /^[[:space:]]*pub fn crash\(/ {
        in_propose = 0
    }
    in_propose && index($0, "if binding != queue.binding") {
        stale_gate_count++
        stale_gate_line = NR
    }
    in_propose && index($0, "if queue.mode == PolicyMode::Fallback") {
        supervisor_gate_count++
        supervisor_gate_line = NR
    }
    in_propose && index($0, "if !queue.contains_task(task_id)") {
        task_gate_count++
        task_gate_line = NR
    }
    in_propose && index($0, "let previous_lease_deadline_tick = queue.lease_deadline_tick;") {
        capture_count++
        capture_line = NR
    }
    in_propose && index($0, "queue.lease_deadline_tick = queue.tick.saturating_add(queue.lease_ticks);") {
        renew_count++
        renew_line = NR
    }
    in_propose && index($0, "queue.pending = Some(Proposal {") {
        publish_count++
        publish_line = NR
    }
    END {
        if (stale_gate_count != 1 || supervisor_gate_count != 1 || task_gate_count != 1 ||
            capture_count != 1 || renew_count != 1 || publish_count != 1) {
            print "scheduler lease source gate: expected three reject gates and one capture/renew/publish" > "/dev/stderr"
            exit 1
        }
        if (!(stale_gate_line < supervisor_gate_line &&
              supervisor_gate_line < task_gate_line &&
              task_gate_line < capture_line &&
              capture_line < renew_line &&
              renew_line < publish_line)) {
            print "scheduler lease source gate: renewal escaped accepted-proposal critical section" > "/dev/stderr"
            exit 1
        }
        print "scheduler lease source gate: PASS rejected_proposals_do_not_renew=true accepted_proposal_renews_before_publication=true"
    }
' "$source_file"
