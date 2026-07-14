#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
production=${1:-$repo_root/crates/nexus-ostd-virtio/src/production.rs}
lib=${2:-$repo_root/crates/nexus-ostd-virtio/src/lib.rs}
portal=${3:-$repo_root/crates/nexus-ostd-virtio/src/portal.rs}

fail() {
    echo "production VirtIO substrate assertion failed: $*" >&2
    exit 1
}

rust_block() {
    local start=$1
    local source=$2
    awk -v start="$start" '
        $0 ~ start { found = 1 }
        found {
            print
            line = $0
            opens = gsub(/\{/, "", line)
            line = $0
            closes = gsub(/\}/, "", line)
            depth += opens - closes
            if (opens > 0) seen_open = 1
            if (seen_open && depth == 0) exit
        }
        END { if (!found || !seen_open || depth != 0) exit 1 }
    ' "$source"
}

declaration_prefix() {
    local declaration=$1
    local source=$2
    awk -v declaration="$declaration" '
        $0 ~ declaration {
            start = NR - 1
            while (start > 0 && lines[start] !~ /^[[:space:]]*$/) start--
            for (line = start + 1; line < NR; line++) print lines[line]
            print
            found = 1
            exit
        }
        { lines[NR] = $0 }
        END { if (!found) exit 1 }
    ' "$source"
}

has_manual_clone_or_copy() {
    local type=$1
    local source=$2
    awk -v type="$type" '
        /^[[:space:]]*impl([[:space:]<]|$)/ {
            signature = $0
            while (signature !~ /\{/ && (getline next_line) > 0) {
                signature = signature " " next_line
            }
            if (signature ~ /(Clone|Copy)/ && signature ~ /for[[:space:]]*/ && signature ~ type) {
                found = 1
            }
        }
        END { exit found ? 0 : 1 }
    ' "$source"
}

for source in "$production" "$lib" "$portal"; do
    [[ -f $source && ! -L $source ]] || fail "missing regular source: $source"
done

if grep -Eq '\b(IoGate|EffectAuthority|cser_transition_gates)\b' "$production"; then
    fail 'hardware facade imports or owns semantic registry authority'
fi
grep -Fq 'pub struct Portal {' "$portal" || fail 'legacy Stage 5B Portal disappeared'
grep -Fq 'gate: IoGate<4>,' "$portal" || fail 'legacy Stage 5B gate disappeared'
grep -Fq 'pub type EffectAuthority = IoIdentity;' "$portal" \
    || fail 'legacy Stage 5B authority regression API disappeared'

grep -Fq 'pub const fn from_coordinates(' "$production" \
    || fail 'registry envelopes cannot reconstruct descriptive identity'
for getter in device_session device_bdf queue descriptor_token device_generation; do
    grep -Fq "pub const fn $getter" "$production" \
        || fail "descriptive identity lacks $getter"
done

device_struct=$(rust_block '^pub struct ProductionDevice [{]' "$production") \
    || fail 'cannot isolate ProductionDevice'
grep -Fq 'device_bdf: DeviceBdf,' <<<"$device_struct" \
    || fail 'production device does not retain its one claimed BDF'
grep -Fq 'active: Option<ActiveSession>,' <<<"$device_struct" \
    || fail 'production device does not serialize one active hardware lifecycle'
device_constructor=$(rust_block '^    pub fn for_owned_device' "$production") \
    || fail 'cannot isolate ProductionDevice constructor'
grep -Fq 'let device_function = root.claim_device_function();' <<<"$device_constructor" \
    || fail 'production device can bypass the opaque Root singleton claim'

prepared_struct=$(rust_block '^pub struct PreparedRequest [{]' "$production") \
    || fail 'cannot isolate PreparedRequest'
prepared_prefix=$(declaration_prefix '^pub struct PreparedRequest [{]' "$production") \
    || fail 'cannot isolate PreparedRequest declaration prefix'
for owner in \
    'transport: ManuallyDrop<PciTransport>,' \
    'queue: ManuallyDrop<PreparedQueue>,' \
    'buffers: ManuallyDrop<Pin<Box<RequestBuffers>>>,'; do
    grep -Fq "$owner" <<<"$prepared_struct" \
        || fail "PreparedRequest does not retain owner: $owner"
done
if grep -Eq '#\[derive\([^]]*(Clone|Copy)' <<<"$prepared_prefix"; then
    fail 'PreparedRequest became Clone or Copy'
fi
if has_manual_clone_or_copy PreparedRequest "$production"; then
    fail 'PreparedRequest gained a handwritten Clone or Copy implementation'
fi

prepared_drop=$(rust_block '^impl Drop for PreparedRequest [{]' "$production") \
    || fail 'cannot isolate PreparedRequest Drop'
grep -Fq 'Fail closed.' <<<"$prepared_drop" \
    || fail 'PreparedRequest Drop no longer documents fail-closed retention'
if grep -Eq '(ManuallyDrop::take|into_inner|drop\(self\.|\.take\(\))' <<<"$prepared_drop"; then
    fail 'PreparedRequest Drop releases an unresolved hardware owner'
fi

prepare=$(rust_block '^    pub fn prepare_read_sector0' "$production") \
    || fail 'cannot isolate production preparation'
grep -Fq 'Result<PreparedRequest, PrepareReadError>' <<<"$prepare" \
    || fail 'production preparation is not a recoverable Result'
grep -Fq 'queue.prepare_add(&inputs, &mut outputs)' <<<"$prepare" \
    || fail 'production preparation bypasses split VirtIO preparation'
grep -Fq 'descriptor_token: prepared.token(),' <<<"$prepare" \
    || fail 'prepared descriptor token is not frozen into identity'
grep -Fq 'queue: ManuallyDrop::new(prepared),' <<<"$prepare" \
    || fail 'prepared queue is not transferred into the linear facade token'
grep -Fq 'rollback_unexposed_preparation(' <<<"$prepare" \
    || fail 'production validation failures bypass complete rollback'
grep -Fq 'dma::try_arm_request_bounce(self.device_generation)' <<<"$prepare" \
    || fail 'request DMA allocation cannot return a rollback error'
active_reject=$(grep -nF 'if self.active.is_some() {' <<<"$prepare" | cut -d: -f1)
hardware_begin=$(grep -nF 'pci::enable_device_for_prepare(root, self.device_function);' \
    <<<"$prepare" | cut -d: -f1)
[[ -n $active_reject && -n $hardware_begin && $active_reject -lt $hardware_begin ]] \
    || fail 'overlapping active session is not rejected before hardware mutation'
prepared_line=$(grep -nF 'let prepared = match unsafe { queue.prepare_add' <<<"$prepare" | cut -d: -f1)
exposed_line=$(grep -nF 'dma::mark_queue_exposed(self.device_generation);' <<<"$prepare" | cut -d: -f1)
finish_line=$(grep -nF 'transport.finish_init();' <<<"$prepare" | cut -d: -f1)
sequence_line=$(grep -nF 'self.next_session_sequence = next_sequence;' <<<"$prepare" | cut -d: -f1)
[[ -n $prepared_line && -n $exposed_line && -n $finish_line && -n $sequence_line \
    && $prepared_line -lt $exposed_line && $exposed_line -lt $finish_line \
    && $finish_line -lt $sequence_line ]] \
    || fail 'queue exposure, DRIVER_OK, or session sequence precedes successful preparation'
if grep -Eq '(panic!|forget\(|\.expect\(|assert(_eq|_ne)?!)' <<<"$prepare"; then
    fail 'recoverable preparation retained a panic or owner-forget validation path'
fi

rollback=$(rust_block '^fn rollback_unexposed_preparation' "$production") \
    || fail 'cannot isolate unexposed preparation rollback'
for rollback_step in \
    'transport.set_status(DeviceStatus::empty());' \
    'pci::disable_bus_master(root, device_function);' \
    'drop(queue);' \
    'drop(transport);' \
    'pci::release_transport_claims()' \
    'pci::restore_device_command(root, device_function, original_command);' \
    'dma::abort_unexposed_generation(generation);'; do
    grep -Fq "$rollback_step" <<<"$rollback" \
        || fail "preparation rollback omits: $rollback_step"
done

preflight=$(rust_block '^    pub fn preflight_publish' "$production") \
    || fail 'cannot isolate publication preflight'
grep -Fq 'expected: DeviceSessionIdentity' <<<"$preflight" \
    || fail 'publication preflight cannot validate registry coordinates'
grep -Fq 'self.identity != expected' <<<"$preflight" \
    || fail 'publication preflight does not reject a foreign identity'
grep -Fq 'self.queue.token() != self.identity.descriptor_token' <<<"$preflight" \
    || fail 'publication preflight does not bind the queue token'
if grep -Eq '(ManuallyDrop::take|forget\(|\.take\(\)|self\.[[:alnum:]_]+[[:space:]]*=)' <<<"$preflight"; then
    fail 'failed publication preflight can mutate or release an owner'
fi

publish=$(rust_block '^    pub fn publish_prepared' "$production") \
    || fail 'cannot isolate split publication'
grep -Fq 'let (queue, _token) = prepared.publish_prepared();' <<<"$publish" \
    || fail 'facade publication bypasses the canonical split Release'
after_release=$(awk '
    /let \(queue, _token\) = prepared\.publish_prepared\(\);/ { visible = 1; next }
    visible { print }
' <<<"$publish")
if grep -Eq '(assert(_eq|_ne)?!|panic!|expect\(|unwrap\(|Result<|\?|Box::|Vec|collect\(|push\(|insert\()' \
    <<<"$after_release"; then
    fail 'facade performs a failing or allocating operation after Release publication'
fi

cancel=$(rust_block '^    pub fn cancel_prepared' "$production") \
    || fail 'cannot isolate split cancellation'
grep -Fq 'prepared.cancel_prepared(&inputs, &mut outputs)' <<<"$cancel" \
    || fail 'facade cancellation does not return the exact original buffers'

notification=$(rust_block '^    pub fn notify' "$production") \
    || fail 'cannot isolate post-publication notification resolution'
for required in \
    'if self.notification_resolved {' \
    'NotificationDisposition::AlreadyResolved' \
    '.should_notify()' \
    '.notify(QUEUE_INDEX);' \
    'NotificationDisposition::Kicked' \
    'NotificationDisposition::Suppressed' \
    'self.notification_resolved = true;'; do
    grep -Fq "$required" <<<"$notification" \
        || fail "notification resolution lacks: $required"
done
if grep -Eq '(assert(_eq|_ne)?!|panic!)' <<<"$notification"; then
    fail 'notification suppression or replay can panic away its linear owner'
fi

completion_progress=$(rust_block '^pub enum CompletionProgress [{]' "$production") \
    || fail 'cannot isolate linear completion progress'
for variant in Complete Pending Failed; do
    grep -Fq "$variant(" <<<"$completion_progress" \
        || fail "completion progress lacks $variant"
done
poll=$(rust_block '^    pub fn poll_completion' "$production") \
    || fail 'cannot isolate bounded completion poll'
grep -Fq 'pub fn poll_completion(mut self) -> CompletionProgress' <<<"$poll" \
    || fail 'completion poll does not return linear progress'
for retained_path in \
    'CompletionProgress::Pending(PendingCompletion {' \
    'CompletionFailure::NotificationUnresolved' \
    'CompletionFailure::WrongToken' \
    'CompletionFailure::Pop(error)' \
    'CompletionFailure::UnexpectedUsedLength' \
    'CompletionFailure::DeviceResponse(response)' \
    'CompletionFailure::ShareAccountingMismatch'; do
    grep -Fq "$retained_path" <<<"$poll" \
        || fail "completion poll lacks retained path: $retained_path"
done
if grep -Eq '(assert_eq!\(observed|expect\("pop matching|panic!)' <<<"$poll"; then
    fail 'completion validation can still panic away its linear owner'
fi
for successor in PendingCompletion FailedCompletion; do
    successor_impl=$(rust_block "^impl $successor [{]" "$production") \
        || fail "cannot isolate $successor"
    grep -Fq 'pub fn begin_reset' <<<"$successor_impl" \
        || fail "$successor cannot begin mandatory reset"
done
grep -Fq 'descriptor_popped: bool,' "$production" \
    || fail 'completion/reset path does not retain descriptor-pop state'
grep -Fq 'if used_len != EXPECTED_USED_LEN {' <<<"$poll" \
    || fail 'completion can accept a short or oversized output as a complete sector read'
used_length_line=$(grep -nF 'if used_len != EXPECTED_USED_LEN {' <<<"$poll" | cut -d: -f1)
response_status_line=$(grep -nF 'let response = request_buffers.response.status();' \
    <<<"$poll" | cut -d: -f1)
[[ -n $used_length_line && -n $response_status_line \
    && $used_length_line -lt $response_status_line ]] \
    || fail 'completion reads device status before validating the complete output length'

generation_preflight=$(rust_block '^    pub fn prepare_generation_advance' "$production") \
    || fail 'cannot isolate generation prevalidation'
grep -Fq 'Result<PreparedGenerationAdvance' <<<"$generation_preflight" \
    || fail 'generation advance has no failure-atomic prevalidation result'
for rejection in NoActiveSession WrongIdentity AlreadyApplied GenerationOverflow; do
    grep -Fq "ResetGenerationError::$rejection" <<<"$generation_preflight" \
        || fail "generation prevalidation lacks $rejection rejection"
done

generation_apply=$(rust_block '^    pub fn apply[(]self[)] -> u64' "$production") \
    || fail 'cannot isolate infallible generation apply'
for assignment in \
    '*self.active_reset_acknowledged = true;' \
    '*self.device_generation = self.next_generation;' \
    '*self.reset_generation_applied = true;'; do
    grep -Fq "$assignment" <<<"$generation_apply" \
        || fail "generation apply lacks direct write: $assignment"
done
if grep -Eq '(if |match |loop |for |while |assert|panic!|expect\(|unwrap\(|Result<|\?|Box::|Vec|collect\(|push\(|insert\()' \
    <<<"$generation_apply"; then
    fail 'generation apply regained branching, failure, lookup, or allocation'
fi

if grep -Fq 'pub fn mark_quiesced' "$production"; then
    fail 'software quiescence can still advance outside a prepared apply plan'
fi
quiescence_preflight=$(rust_block '^    pub fn prepare_quiescence_apply' "$production") \
    || fail 'cannot isolate quiescence prevalidation'
grep -Fq 'Result<PreparedQuiescenceApply' <<<"$quiescence_preflight" \
    || fail 'quiescence has no failure-atomic prevalidation result'
for rejection in \
    NoActiveSession WrongIdentity ResetNotApplied WrongGeneration WrongCompletedPages AlreadyApplied; do
    grep -Fq "QuiescenceApplyError::$rejection" <<<"$quiescence_preflight" \
        || fail "quiescence prevalidation lacks $rejection rejection"
done
if grep -Eq '(ManuallyDrop::take|forget\(|\.take\(\)|self\.[[:alnum:]_]+[[:space:]]*=|closure\.applied[[:space:]]*=)' \
    <<<"$quiescence_preflight"; then
    fail 'failed quiescence preflight can mutate or release an owner'
fi

quiescence_apply=$(rust_block '^    pub fn apply[(]self[)] -> DeviceSessionIdentity' "$production") \
    || fail 'cannot isolate infallible quiescence apply'
grep -Fq '*self.closure_applied = true;' <<<"$quiescence_apply" \
    || fail 'quiescence apply does not consume its exact closure receipt'
grep -Fq '*self.active = None;' <<<"$quiescence_apply" \
    || fail 'quiescence apply does not release the active facade slot'
if grep -Eq '(if |match |loop |for |while |assert|panic!|expect\(|unwrap\(|Result<|\?|Box::|Vec|collect\(|push\(|insert\()' \
    <<<"$quiescence_apply"; then
    fail 'quiescence apply regained branching, failure, lookup, or allocation'
fi

for export in \
    CompletionFailure CompletionProgress FailedCompletion NotificationDisposition PendingCompletion PrepareReadError \
    PreparedGenerationAdvance PreparedQuiescenceApply PublishIdentityError QuiescenceApplyError \
    ResetGenerationError; do
    grep -Fq "$export" "$lib" || fail "public facade omits $export"
done

echo 'production VirtIO substrate: PASS authority=registry-external identity=descriptive+reconstructible physical_owner=one-bdf+one-active-session preparation=result+full-unexposed-rollback+sequence-atomic linear_owner=non-clone+fail-closed preflight=failure-atomic publication=infallible+post-release-moves-only notification=kick-or-suppressed+replay-safe completion=linear+exact-used-length+pending-or-failed-resettable+pop-state cancel=exact-buffers generation=prevalidate+infallible-apply quiescence=prevalidate+infallible-apply legacy_portal=retained'
