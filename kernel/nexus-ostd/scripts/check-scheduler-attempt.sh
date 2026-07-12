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
