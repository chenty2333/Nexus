#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
production=${1:-$repo_root/crates/nexus-ostd-virtio/src/production.rs}
lib=${2:-$repo_root/crates/nexus-ostd-virtio/src/lib.rs}
portal=${3:-$repo_root/crates/nexus-ostd-virtio/src/portal.rs}
pci=${4:-$repo_root/crates/nexus-ostd-virtio/src/pci.rs}

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

rust_impl_method() {
    local type=$1
    local method=$2
    local source=$3
    awk -v impl_pattern="^impl[[:space:]]+$type[[:space:]]*[{]" \
        -v method_pattern="^[[:space:]]+pub fn[[:space:]]+$method[(]" '
        function brace_delta(value, copy, opens, closes) {
            copy = value
            opens = gsub(/\{/, "", copy)
            copy = value
            closes = gsub(/\}/, "", copy)
            return opens - closes
        }
        $0 ~ impl_pattern {
            in_impl = 1
            impl_depth = brace_delta($0)
            next
        }
        in_impl {
            if (!found && $0 ~ method_pattern) found = 1
            if (found) {
                print
                delta = brace_delta($0)
                method_depth += delta
                if (delta > 0) seen_open = 1
                if (seen_open && method_depth == 0) exit
            }
            impl_depth += brace_delta($0)
            if (impl_depth == 0 && !found) in_impl = 0
        }
        END { if (!found || !seen_open || method_depth != 0) exit 1 }
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

for source in "$production" "$lib" "$portal" "$pci"; do
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

# The PCI route is descriptive; only Root's one-shot claim and linear
# owner/epoch tokens authorize mask state transitions.
pci_impl=$(awk '/^#\[cfg\(test\)\]$/ { exit } { print }' "$pci")
root_struct=$(rust_block '^pub struct Root [{]' "$pci") \
    || fail 'cannot isolate PCI Root owner'
for field in \
    'intx_route: IntxRoute,' \
    'intx_owner_id: u64,' \
    'intx_state: IntxOwnershipState,'; do
    grep -Fq "$field" <<<"$root_struct" || fail "PCI Root lacks INTx owner state: $field"
done
for token in MaskedIntx UnmaskedIntx; do
    token_struct=$(rust_block "^pub struct $token [{]" "$pci") \
        || fail "cannot isolate $token"
    for field in 'owner_id: u64,' 'epoch: u64,' 'route: IntxRoute,'; do
        grep -Fq "$field" <<<"$token_struct" || fail "$token lacks private $field"
    done
    token_prefix=$(declaration_prefix "^pub struct $token [{]" "$pci") \
        || fail "cannot isolate $token declaration prefix"
    if grep -Eq '#\[derive\([^]]*(Clone|Copy)' <<<"$token_prefix" \
        || has_manual_clone_or_copy "$token" "$pci"; then
        fail "$token became Clone or Copy"
    fi
done
route_getter=$(rust_block '^    pub const fn intx_route' "$pci") \
    || fail 'cannot isolate descriptive INTx route getter'
grep -Fq 'self.intx_route' <<<"$route_getter" \
    || fail 'INTx route getter no longer returns the discovered route'
if grep -Eq '(intx_state|set_intx_mask|MaskedIntx|UnmaskedIntx)' <<<"$route_getter"; then
    fail 'copyable INTx route regained transition authority'
fi

grep -Fq 'const INTERRUPT_CONFIG_OFFSET: u8 = 0x3c;' "$pci" \
    || fail 'INTx route no longer reads the standard PCI line/pin register'
decode_route=$(rust_block '^const fn decode_intx_route' "$pci") \
    || fail 'cannot isolate INTx route decoder'
for required in \
    'line: interrupt_config as u8,' \
    'pin: (interrupt_config >> 8) as u8,'; do
    grep -Fq "$required" <<<"$decode_route" || fail "INTx route decoder lacks: $required"
done

command_mask=$(rust_block '^const fn command_with_intx_mask' "$pci") \
    || fail 'cannot isolate INTx command-bit projection'
for required in \
    'command.union(Command::INTERRUPT_DISABLE)' \
    'command.difference(Command::INTERRUPT_DISABLE)'; do
    grep -Fq "$required" <<<"$command_mask" || fail "INTx command projection lacks: $required"
done
command_constant_count=$(grep -F -o 'Command::' <<<"$command_mask" | wc -l)
[[ $command_constant_count == 2 ]] \
    || fail 'INTx command projection references a command bit other than INTERRUPT_DISABLE'

set_intx=$(rust_block '^fn set_intx_mask' "$pci") \
    || fail 'cannot isolate typed INTx command write/readback'
for required in \
    '-> IntxCommandObservation' \
    'let (_, before) = root.inner.get_status_command(device_function);' \
    'let expected = command_with_intx_mask(before, masked);' \
    'root.inner.set_command(device_function, expected);' \
    'let (_, observed) = root.inner.get_status_command(device_function);' \
    'IntxCommandObservation {' \
    'before,' \
    'expected,' \
    'observed,'; do
    grep -Fq -- "$required" <<<"$set_intx" || fail "typed INTx write lacks: $required"
done
if grep -Eq '(assert|panic!|unwrap\(|expect\()' <<<"$set_intx"; then
    fail 'typed INTx write can panic after its PCI side effect'
fi

ownership_state=$(rust_block '^enum IntxOwnershipState' "$pci") \
    || fail 'cannot isolate INTx ownership state'
grep -Fq 'Poisoned { epoch: u64, observed_masked: bool }' <<<"$ownership_state" \
    || fail 'INTx ownership state cannot retain a poisoned readback'
validate_intx=$(rust_block '^    fn validate_intx_token' "$pci") \
    || fail 'cannot isolate owner/route/epoch validation'
for required in \
    'owner_id != self.intx_owner_id' \
    'route != self.intx_route' \
    'IntxTransitionError::ForeignOwner' \
    'IntxOwnershipState::Masked { epoch }' \
    'IntxOwnershipState::Unmasked { epoch }' \
    'IntxTransitionError::WrongState' \
    'current_epoch != epoch' \
    'IntxTransitionError::StaleEpoch'; do
    grep -Fq "$required" <<<"$validate_intx" || fail "INTx token validation lacks: $required"
done
if grep -Fq 'return Ok(())' <<<"$validate_intx"; then
    fail 'INTx token validation contains an unconditional early success'
fi

masked_constructor_count=$(grep -F -c 'MaskedIntx {' <<<"$pci_impl" || true)
unmasked_constructor_count=$(grep -F -c 'UnmaskedIntx {' <<<"$pci_impl" || true)
[[ $masked_constructor_count == 5 && $unmasked_constructor_count == 3 ]] \
    || fail "unexpected INTx token construction surface (masked=$masked_constructor_count unmasked=$unmasked_constructor_count)"

claim_intx=$(rust_block '^    pub fn claim_masked_intx' "$pci") \
    || fail 'cannot isolate initial masked INTx claim'
unmask_intx=$(rust_block '^    pub fn unmask_intx' "$pci") \
    || fail 'cannot isolate INTx unmask transition'
mask_intx=$(rust_block '^    pub fn mask_intx' "$pci") \
    || fail 'cannot isolate INTx mask transition'
recover_intx=$(rust_block '^    pub fn recover_masked_intx_fail_closed' "$pci") \
    || fail 'cannot isolate one-way fail-closed INTx recovery'
for required in \
    'self.intx_state != IntxOwnershipState::Unclaimed' \
    'IntxTransitionError::AlreadyClaimed' \
    '!self.has_valid_intx_route()' \
    'IntxTransitionError::InvalidRoute' \
    'let observation = set_intx_mask(self, true);' \
    'if !observation.is_exact() {' \
    'IntxOwnershipState::Poisoned {' \
    'return Err(observation.error(true, true));' \
    'self.intx_state = IntxOwnershipState::Masked { epoch };' \
    'owner_id: self.intx_owner_id,'; do
    grep -Fq "$required" <<<"$claim_intx" || fail "initial INTx claim lacks: $required"
done
for required in \
    'IntxOwnershipState::Unclaimed => return Err(IntxTransitionError::WrongState)' \
    'let epoch = next_intx_epoch(current_epoch);' \
    'let observation = set_intx_mask(self, true);' \
    'if !observation.is_exact() {' \
    'self.intx_state = IntxOwnershipState::Poisoned {' \
    'self.intx_state = IntxOwnershipState::Masked { epoch };' \
    'Ok(MaskedIntx {'; do
    grep -Fq "$required" <<<"$recover_intx" || fail "fail-closed INTx recovery lacks: $required"
done
if grep -Fq 'set_intx_mask(self, false)' <<<"$recover_intx"; then
    fail 'fail-closed INTx recovery can unmask the device'
fi
for transition in "$unmask_intx" "$mask_intx"; do
    for required in \
        'self.validate_intx_token(' \
        'return Err(IntxTransitionFailure {' \
        'let observation = set_intx_mask(self,' \
        'if !observation.is_exact() {' \
        'let restored = restore_intx_command(self, observation.before);' \
        'IntxOwnershipState::Poisoned {' \
        'error: observation.error(' \
        'owner_id: self.intx_owner_id,' \
        'route: self.intx_route,'; do
        grep -Fq "$required" <<<"$transition" || fail "INTx transition lacks: $required"
    done
done
grep -Fq 'IntxTransitionFailure<MaskedIntx>' <<<"$unmask_intx" \
    || fail 'failed unmask does not return the exact masked token'
grep -Fq 'let epoch = next_intx_epoch(masked.epoch);' <<<"$unmask_intx" \
    || fail 'unmask does not prevalidate its next owner epoch'
for required in \
    'let (_, observed_before_unmask) =' \
    'self.inner.get_status_command(self.device_function);' \
    'if !observed_before_unmask.contains(Command::INTERRUPT_DISABLE) {' \
    'let recovery = set_intx_mask(self, true);' \
    'epoch: masked.epoch,' \
    'observed_masked: recovery.observed_masked(),' \
    'error: recovery.error(true, true),' \
    'error: IntxTransitionError::CommandReadbackMismatch {' \
    'expected_masked: true,' \
    'observed_masked: false,' \
    'other_bits_changed: false,' \
    'poisoned: false,'; do
    grep -Fq "$required" <<<"$unmask_intx" \
        || fail "unmask masked-command precondition lacks: $required"
done
grep -Fq 'set_intx_mask(self, false);' <<<"$unmask_intx" \
    || fail 'unmask does not change the PCI command through the canonical helper'
grep -Fq 'IntxTransitionFailure<UnmaskedIntx>' <<<"$mask_intx" \
    || fail 'failed mask does not return the exact unmasked token'
grep -Fq 'let epoch = next_intx_epoch(unmasked.epoch);' <<<"$mask_intx" \
    || fail 'mask does not prevalidate its next owner epoch'
grep -Fq 'set_intx_mask(self, true);' <<<"$mask_intx" \
    || fail 'mask does not change the PCI command through the canonical helper'
unmask_epoch_line=$(grep -nF 'let epoch = next_intx_epoch(masked.epoch);' \
    <<<"$unmask_intx" | cut -d: -f1)
unmask_preread_line=$(grep -nF 'let (_, observed_before_unmask) =' \
    <<<"$unmask_intx" | cut -d: -f1)
unmask_precondition_line=$(grep -nF \
    'if !observed_before_unmask.contains(Command::INTERRUPT_DISABLE) {' \
    <<<"$unmask_intx" | cut -d: -f1)
unmask_recovery_line=$(grep -nF 'let recovery = set_intx_mask(self, true);' \
    <<<"$unmask_intx" | cut -d: -f1)
unmask_write_line=$(grep -nF 'set_intx_mask(self, false);' <<<"$unmask_intx" | cut -d: -f1)
mask_epoch_line=$(grep -nF 'let epoch = next_intx_epoch(unmasked.epoch);' \
    <<<"$mask_intx" | cut -d: -f1)
mask_write_line=$(grep -nF 'set_intx_mask(self, true);' <<<"$mask_intx" | cut -d: -f1)
[[ -n $unmask_epoch_line && -n $unmask_preread_line \
    && -n $unmask_precondition_line && -n $unmask_recovery_line \
    && -n $unmask_write_line \
    && $unmask_epoch_line -lt $unmask_preread_line \
    && $unmask_preread_line -lt $unmask_precondition_line \
    && $unmask_precondition_line -lt $unmask_recovery_line \
    && $unmask_recovery_line -lt $unmask_write_line \
    && -n $mask_epoch_line && -n $mask_write_line \
    && $mask_epoch_line -lt $mask_write_line ]] \
    || fail 'INTx prevalidation or masked-command observation follows hardware mutation'
if grep -Fq 'pub fn mask_intx(&mut self, route: IntxRoute)' <<<"$pci_impl" \
    || grep -Fq 'into_route(self)' <<<"$pci_impl"; then
    fail 'descriptive INTx route can bypass linear owner-state transitions'
fi

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

production_impl=$(awk '/^#\[cfg\(test\)\]$/ { exit } { print }' "$production")
intent_failure=$(rust_block '^pub struct HardwareIntentFailure' "$production") \
    || fail 'cannot isolate hardware-intent failure owner'
for field in 'error: HardwareIntentError,' 'owner: T,'; do
    grep -Fq "$field" <<<"$intent_failure" \
        || fail "hardware-intent failure drops field: $field"
done
intent_failure_impl=$(rust_block '^impl<T> HardwareIntentFailure<T>' "$production") \
    || fail 'cannot isolate hardware-intent failure recovery'
for required in \
    'pub const fn error(&self) -> HardwareIntentError' \
    'pub const fn owner(&self) -> &T' \
    'pub fn into_owner(self) -> T' \
    'self.owner'; do
    grep -Fq "$required" <<<"$intent_failure_impl" \
        || fail "hardware-intent failure cannot return owner: $required"
done
intent_failure_prefix=$(declaration_prefix '^pub struct HardwareIntentFailure' "$production") \
    || fail 'cannot isolate hardware-intent failure declaration prefix'
if grep -Eq '#\[derive\([^]]*(Clone|Copy)' <<<"$intent_failure_prefix" \
    || has_manual_clone_or_copy HardwareIntentFailure "$production"; then
    fail 'hardware-intent failure can duplicate a returned owner'
fi

for intent_spec in \
    'PreparedCancelIntent:PreparedRequest' \
    'PreparedPublishedResetIntent:PublishedRequest'; do
    intent=${intent_spec%%:*}
    owner=${intent_spec#*:}
    intent_struct=$(rust_block "^pub struct $intent [{]" "$production") \
        || fail "cannot isolate $intent"
    grep -Fq "request: $owner," <<<"$intent_struct" \
        || fail "$intent does not retain the real $owner"
    if grep -Fq 'DeviceSessionIdentity' <<<"$intent_struct"; then
        fail "$intent replaced its real owner with descriptive identity"
    fi
    intent_prefix=$(declaration_prefix "^pub struct $intent [{]" "$production") \
        || fail "cannot isolate $intent declaration prefix"
    if grep -Eq '#\[derive\([^]]*(Clone|Copy)' <<<"$intent_prefix" \
        || has_manual_clone_or_copy "$intent" "$production"; then
        fail "$intent became Clone or Copy"
    fi
    constructor_count=$(grep -F -c "$intent {" <<<"$production_impl" || true)
    [[ $constructor_count == 3 ]] \
        || fail "$intent gained a descriptive or replayable constructor (count=$constructor_count)"
done

polling_prepare=$(rust_block '^    pub fn prepare_read_sector0[(]' "$production") \
    || fail 'cannot isolate polling preparation wrapper'
irq_prepare=$(rust_block '^    pub fn prepare_read_sector0_irq[(]' "$production") \
    || fail 'cannot isolate IRQ preparation wrapper'
prepare=$(rust_block '^    fn prepare_read_sector0_with_mode[(]' "$production") \
    || fail 'cannot isolate shared production preparation'
grep -Fq 'self.prepare_read_sector0_with_mode(root, CompletionMode::Polling)' \
    <<<"$polling_prepare" || fail 'polling wrapper bypasses shared preparation mode'
grep -Fq 'self.prepare_read_sector0_with_mode(root, CompletionMode::Interrupt)' \
    <<<"$irq_prepare" || fail 'IRQ wrapper bypasses shared preparation mode'
for wrapper in "$polling_prepare" "$irq_prepare"; do
    grep -Fq 'Result<PreparedRequest, PrepareReadError>' <<<"$wrapper" \
        || fail 'production preparation wrapper is not a recoverable Result'
    if grep -Fq 'queue.prepare_add' <<<"$wrapper"; then
        fail 'production preparation forked queue ownership outside the shared helper'
    fi
done
grep -Fq 'completion_mode: CompletionMode' <<<"$prepare" \
    || fail 'shared preparation lacks an explicit completion mode'
grep -Fq 'queue.prepare_add(&inputs, &mut outputs)' <<<"$prepare" \
    || fail 'shared production preparation bypasses split VirtIO preparation'
grep -Fq 'queue.set_dev_notify(completion_mode.device_notifications_enabled());' <<<"$prepare" \
    || fail 'shared preparation does not bind device notification policy to completion mode'
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

cancel_preflight=$(rust_block '^    pub fn preflight_cancel' "$production") \
    || fail 'cannot isolate prepared-cancel intent preflight'
for required in \
    'self,' \
    'expected_cancel_identity: DeviceSessionIdentity,' \
    'Result<PreparedCancelIntent, HardwareIntentFailure<PreparedRequest>>' \
    'self.identity != expected_cancel_identity' \
    'HardwareIntentError::WrongIdentity' \
    'self.queue.token() != self.identity.descriptor_token' \
    'HardwareIntentError::DescriptorTokenMismatch' \
    'dma::request_share_counts_checked(self.identity.device_generation)' \
    'if observed != Some((3, 0)) {' \
    'HardwareIntentError::RequestShareStateMismatch { observed }' \
    'Ok(PreparedCancelIntent { request: self })'; do
    grep -Fq "$required" <<<"$cancel_preflight" \
        || fail "prepared-cancel preflight lacks: $required"
done
cancel_owner_returns=$(grep -F -c 'owner: self,' <<<"$cancel_preflight" || true)
[[ $cancel_owner_returns == 3 ]] \
    || fail 'prepared-cancel rejection does not return the original owner on every path'
if grep -Eq '(ManuallyDrop::take|forget\(|\.take\(\)|unsafe[[:space:]]*\{|self\.[[:alnum:]_]+[[:space:]]*=)' \
    <<<"$cancel_preflight"; then
    fail 'prepared-cancel preflight can mutate or release its owner'
fi

published_reset_preflight=$(rust_impl_method PublishedRequest preflight_reset "$production") \
    || fail 'cannot isolate published-reset intent preflight'
for required in \
    'self,' \
    'expected_reset_identity: DeviceSessionIdentity,' \
    'Result<PreparedPublishedResetIntent, HardwareIntentFailure<PublishedRequest>>' \
    'self.identity != expected_reset_identity' \
    'HardwareIntentError::WrongIdentity' \
    'self.transport.is_none() || self.queue.is_none() || self.buffers.is_none()' \
    'HardwareIntentError::MissingResetOwner' \
    'dma::request_share_counts_checked(self.identity.device_generation)' \
    'if observed != Some((3, 0)) {' \
    'HardwareIntentError::RequestShareStateMismatch { observed }' \
    'Ok(PreparedPublishedResetIntent { request: self })'; do
    grep -Fq "$required" <<<"$published_reset_preflight" \
        || fail "published-reset preflight lacks: $required"
done
published_owner_returns=$(grep -F -c 'owner: self,' <<<"$published_reset_preflight" || true)
[[ $published_owner_returns == 3 ]] \
    || fail 'published-reset rejection does not return the original owner on every path'
if grep -Eq '(ManuallyDrop::take|forget\(|\.take\(\)|unsafe[[:space:]]*\{|self\.[[:alnum:]_]+[[:space:]]*=)' \
    <<<"$published_reset_preflight"; then
    fail 'published-reset preflight can mutate or release its owner'
fi

completion_reset_helper=$(rust_block '^fn preflight_completion_reset_owner' "$production") \
    || fail 'cannot isolate completion-reset owner validation'
for required in \
    'request: Option<&PublishedRequest>,' \
    'expected_reset_identity: DeviceSessionIdentity,' \
    'expected_share_counts: (usize, usize),' \
    'let Some(request) = request else {' \
    'HardwareIntentError::MissingResetOwner' \
    'request.identity != expected_reset_identity' \
    'HardwareIntentError::WrongIdentity' \
    'request.transport.is_none() || request.queue.is_none() || request.buffers.is_none()' \
    'dma::request_share_counts_checked(request.identity.device_generation)' \
    'observed != Some(expected_share_counts)' \
    'HardwareIntentError::RequestShareStateMismatch { observed }' \
    'Ok(())'; do
    grep -Fq "$required" <<<"$completion_reset_helper" \
        || fail "completion-reset owner validation lacks: $required"
done
if grep -Eq '(ManuallyDrop::take|forget\(|\.take\(\)|unsafe[[:space:]]*\{|begin_reset|into_reset_session|set_status|notify\(|self\.[[:alnum:]_]+[[:space:]]*=)' \
    <<<"$completion_reset_helper"; then
    fail 'completion-reset owner validation can mutate or release hardware'
fi

for preflight_spec in \
    'CompletedRequest:Completed:POPPED_REQUEST_SHARE_COUNTS' \
    'PendingCompletion:Pending:PUBLISHED_REQUEST_SHARE_COUNTS' \
    'FailedCompletion:Failed:expected_share_counts'; do
    completion_owner=${preflight_spec%%:*}
    remainder=${preflight_spec#*:}
    completion_variant=${remainder%%:*}
    share_projection=${remainder#*:}
    completion_preflight=$(rust_impl_method "$completion_owner" preflight_reset "$production") \
        || fail "cannot isolate $completion_owner reset preflight"
    for required in \
        'self,' \
        'expected_reset_identity: DeviceSessionIdentity,' \
        "Result<PreparedRequestResetIntent, HardwareIntentFailure<$completion_owner>>" \
        'preflight_completion_reset_owner(' \
        'self.request.as_ref(),' \
        'expected_reset_identity,' \
        "$share_projection," \
        "owner: PreparedRequestResetOwner::$completion_variant(self)," \
        'Err(error) => Err(HardwareIntentFailure { error, owner: self })'; do
        grep -Fq "$required" <<<"$completion_preflight" \
            || fail "$completion_owner reset preflight lacks: $required"
    done
    completion_owner_returns=$(grep -F -c 'owner: self' <<<"$completion_preflight" || true)
    [[ $completion_owner_returns == 1 ]] \
        || fail "$completion_owner reset rejection does not return its original owner"
    if grep -Eq '(ManuallyDrop::take|forget\(|\.take\(\)|unsafe[[:space:]]*\{|begin_reset|into_reset_session|set_status|notify\(|self\.[[:alnum:]_]+[[:space:]]*=)' \
        <<<"$completion_preflight"; then
        fail "$completion_owner reset preflight can mutate or release its owner"
    fi
done
for required in \
    'let expected_share_counts = if self.descriptor_popped {' \
    'POPPED_REQUEST_SHARE_COUNTS' \
    'PUBLISHED_REQUEST_SHARE_COUNTS'; do
    grep -Fq "$required" <<<"$(rust_impl_method FailedCompletion preflight_reset "$production")" \
        || fail "failed-completion reset preflight loses pop-state projection: $required"
done

completion_reset_owner=$(rust_block '^enum PreparedRequestResetOwner [{]' "$production") \
    || fail 'cannot isolate private completion-reset owner enum'
for variant in \
    'Completed(CompletedRequest)' \
    'Pending(PendingCompletion)' \
    'Failed(FailedCompletion)'; do
    grep -Fq "$variant" <<<"$completion_reset_owner" \
        || fail "completion-reset owner enum lacks $variant"
done
if grep -Eq '^pub([[:space:]]|\()' <<<"$completion_reset_owner"; then
    fail 'completion-reset owner enum became publicly constructible'
fi
completion_reset_owner_prefix=$(declaration_prefix '^enum PreparedRequestResetOwner [{]' "$production") \
    || fail 'cannot isolate completion-reset owner declaration prefix'
if grep -Eq '#\[derive\([^]]*(Clone|Copy)' <<<"$completion_reset_owner_prefix" \
    || has_manual_clone_or_copy PreparedRequestResetOwner "$production"; then
    fail 'completion-reset owner enum became Clone or Copy'
fi

completion_reset_intent=$(rust_block '^pub struct PreparedRequestResetIntent [{]' "$production") \
    || fail 'cannot isolate completion-reset intent'
grep -Fq 'owner: PreparedRequestResetOwner,' <<<"$completion_reset_intent" \
    || fail 'completion-reset intent does not retain its private real-owner enum'
if grep -Fq 'DeviceSessionIdentity' <<<"$completion_reset_intent"; then
    fail 'completion-reset intent replaced its real owner with descriptive identity'
fi
completion_reset_intent_prefix=$(declaration_prefix '^pub struct PreparedRequestResetIntent [{]' "$production") \
    || fail 'cannot isolate completion-reset intent declaration prefix'
if grep -Eq '#\[derive\([^]]*(Clone|Copy)' <<<"$completion_reset_intent_prefix" \
    || has_manual_clone_or_copy PreparedRequestResetIntent "$production"; then
    fail 'completion-reset intent became Clone or Copy'
fi
completion_reset_constructor_count=$(grep -F -c 'PreparedRequestResetIntent {' \
    <<<"$production_impl" || true)
[[ $completion_reset_constructor_count == 5 ]] \
    || fail "completion-reset intent gained a descriptive or replayable constructor (count=$completion_reset_constructor_count)"

completion_reset_identity=$(rust_impl_method PreparedRequestResetIntent identity "$production") \
    || fail 'cannot isolate completion-reset intent identity'
for variant in Completed Pending Failed; do
    grep -Fq "PreparedRequestResetOwner::$variant(request) => request.identity()" \
        <<<"$completion_reset_identity" \
        || fail "completion-reset intent identity loses $variant owner"
done
completion_reset_apply=$(rust_impl_method PreparedRequestResetIntent apply_reset "$production") \
    || fail 'cannot isolate completion-reset intent apply'
grep -Fq 'pub fn apply_reset(self, inject_pending_once: bool) -> ProductionResetTombstone' \
    <<<"$completion_reset_apply" \
    || fail 'completion-reset intent apply is not consuming and infallible'
for variant in Completed Pending Failed; do
    grep -Fq "PreparedRequestResetOwner::$variant(request)" <<<"$completion_reset_apply" \
        || fail "completion-reset intent apply loses $variant owner"
done
completion_begin_reset_count=$(grep -F -c 'request.begin_reset(inject_pending_once)' \
    <<<"$completion_reset_apply" || true)
[[ $completion_begin_reset_count == 3 ]] \
    || fail 'completion-reset intent does not reuse each retained wrapper begin_reset'
if grep -Eq '(from_coordinates|from_identity|loop |for [^ ]+ in |while |assert|panic!|expect\(|unwrap\(|Result<|\?|into_reset_session|Box::|Vec|collect\(|push\(|insert\()' \
    <<<"$completion_reset_apply"; then
    fail 'completion-reset intent regained reconstruction, fallibility, or a second reset path'
fi

cancel_intent_impl=$(rust_block '^impl PreparedCancelIntent [{]' "$production") \
    || fail 'cannot isolate prepared-cancel intent apply'
for required in \
    'pub const fn identity(&self) -> DeviceSessionIdentity' \
    'pub fn apply_reset(self, inject_pending_once: bool) -> ProductionResetTombstone' \
    'self.request' \
    '.cancel_prepared()' \
    '.begin_reset(inject_pending_once)'; do
    grep -Fq "$required" <<<"$cancel_intent_impl" \
        || fail "prepared-cancel intent apply lacks: $required"
done
published_intent_impl=$(rust_block '^impl PreparedPublishedResetIntent [{]' "$production") \
    || fail 'cannot isolate published-reset intent apply'
for required in \
    'pub const fn identity(&self) -> DeviceSessionIdentity' \
    'pub fn apply_reset(self, inject_pending_once: bool) -> ProductionResetTombstone' \
    'self.request' \
    '.into_reset_session(false, false)' \
    '.begin_reset(inject_pending_once)'; do
    grep -Fq "$required" <<<"$published_intent_impl" \
        || fail "published-reset intent apply lacks: $required"
done
for intent_apply in "$cancel_intent_impl" "$published_intent_impl"; do
    if grep -Eq '(from_coordinates|from_identity|if |match |loop |for [^ ]+ in |while |assert|panic!|expect\(|unwrap\(|Result<|\?|Box::|Vec|collect\(|push\(|insert\()' \
        <<<"$intent_apply"; then
        fail 'linear hardware intent regained construction from identity or fallible apply work'
    fi
done

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
grep -Fq 'pub fn poll_completion(self) -> CompletionProgress' <<<"$poll" \
    || fail 'completion poll does not return linear progress'
grep -Fq 'match request.probe_completion_once() {' <<<"$poll" \
    || fail 'polling completion bypasses the shared one-shot validator'
grep -Fq 'for _ in 0..POLL_LIMIT {' <<<"$poll" \
    || fail 'legacy polling completion lost its explicit bounded loop'
grep -Fq 'CompletionProgress::Pending(PendingCompletion {' <<<"$poll" \
    || fail 'bounded polling no longer retains a pending linear owner'

ack_interrupt=$(rust_block '^    pub fn ack_interrupt' "$production") \
    || fail 'cannot isolate VirtIO ISR acknowledgement'
ack_prefix=$(declaration_prefix '^    pub fn ack_interrupt' "$production") \
    || fail 'cannot isolate IRQ acknowledgement contract'
for required in 'Hard-IRQ top-half' 'method intended for hard-IRQ context'; do
    grep -Fq "$required" <<<"$ack_prefix" || fail "IRQ top-half contract lacks: $required"
done
for required in \
    'pub fn ack_interrupt(&mut self) -> InterruptReceipt' \
    '.ack_interrupt();' \
    'identity: self.identity,' \
    'cause: decode_interrupt_status(status),'; do
    grep -Fq "$required" <<<"$ack_interrupt" \
        || fail "IRQ acknowledgement lacks: $required"
done
if grep -Eq '(spin_loop|pop_used|println!|Box::|Vec|collect\(|push\(|insert\()' \
    <<<"$ack_interrupt"; then
    fail 'IRQ top-half acknowledgement gained spin, completion, logging, or allocation work'
fi

irq_completion=$(rust_block '^    pub fn complete_after_interrupt' "$production") \
    || fail 'cannot isolate IRQ completion handoff'
irq_completion_prefix=$(declaration_prefix '^    pub fn complete_after_interrupt' "$production") \
    || fail 'cannot isolate task-context completion contract'
for required in \
    'Task-context completion' \
    'DMA ledger lock' \
    'not run in hard-IRQ context'; do
    grep -Fq "$required" <<<"$irq_completion_prefix" \
        || fail "IRQ completion context contract lacks: $required"
done
for required in \
    'self.identity != receipt.identity' \
    'InterruptNotReadyReason::WrongIdentity' \
    'self.completion_mode != CompletionMode::Interrupt' \
    'InterruptNotReadyReason::PollingRequest' \
    '!receipt.cause.includes_queue()' \
    'InterruptNotReadyReason::NonQueueCause' \
    'match self.probe_completion_once() {' \
    'reason: InterruptNotReadyReason::UsedRingNotReady'; do
    grep -Fq "$required" <<<"$irq_completion" \
        || fail "IRQ completion handoff lacks retained path: $required"
done
if grep -Eq '(spin_loop|pop_used|println!|Box::|Vec|collect\(|push\(|insert\()' \
    <<<"$irq_completion"; then
    fail 'IRQ completion handoff forked the shared validator or gained blocking/allocation work'
fi

completion_probe_progress=$(rust_block '^pub enum CompletionProbeProgress [{]' "$production") \
    || fail 'cannot isolate linear one-step completion result'
for variant in Complete NotReady Failed; do
    grep -Fq "$variant(" <<<"$completion_probe_progress" \
        || fail "one-step completion result lacks $variant"
done
completion_probe=$(rust_block '^    pub fn probe_completion_once' "$production") \
    || fail 'cannot isolate public one-step completion probe'
for required in \
    'pub fn probe_completion_once(self) -> CompletionProbeProgress' \
    'match self.complete_once() {' \
    'CompletionAttempt::Complete(request) => CompletionProbeProgress::Complete(request)' \
    'CompletionAttempt::NotReady(request) => CompletionProbeProgress::NotReady(request)' \
    'CompletionAttempt::Failed(failure) => CompletionProbeProgress::Failed(failure)'; do
    grep -Fq "$required" <<<"$completion_probe" \
        || fail "one-step completion probe lacks: $required"
done
if grep -Eq '(for |while |loop |spin_loop|pop_used|println!|Box::|Vec|collect\(|push\(|insert\()' \
    <<<"$completion_probe"; then
    fail 'public one-step completion probe gained polling, validation fork, logging, or allocation'
fi

complete_once=$(rust_block '^    fn complete_once' "$production") \
    || fail 'cannot isolate one-shot completion probe'
grep -Fq 'self.complete_observed(observed)' <<<"$complete_once" \
    || fail 'one-shot completion bypasses the shared observed-token validator'
if grep -Fq 'spin_loop' <<<"$complete_once"; then
    fail 'one-shot IRQ completion can spin'
fi

completion_validator=$(rust_block '^    fn complete_observed' "$production") \
    || fail 'cannot isolate shared completion validator'
pop_count=$(grep -F -c 'queue.pop_used(expected, &inputs, &mut outputs)' \
    <<<"$production_impl" || true)
[[ $pop_count == 1 ]] \
    || fail "polling and IRQ completion forked descriptor validation (pop_count=$pop_count)"
for retained_path in \
    'CompletionAttempt::NotReady(self)' \
    'CompletionFailure::NotificationUnresolved' \
    'CompletionFailure::WrongToken' \
    'CompletionFailure::Pop(error)' \
    'CompletionFailure::UnexpectedUsedLength' \
    'CompletionFailure::DeviceResponse(response)' \
    'CompletionFailure::ShareAccountingMismatch'; do
    grep -Fq "$retained_path" <<<"$completion_validator" \
        || fail "shared completion validator lacks retained path: $retained_path"
done
if grep -Eq '(assert_eq!\(observed|expect\("pop matching|panic!|spin_loop)' \
    <<<"$completion_validator"; then
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
grep -Fq 'if used_len != EXPECTED_USED_LEN {' <<<"$completion_validator" \
    || fail 'completion can accept a short or oversized output as a complete sector read'
used_length_line=$(grep -nF 'if used_len != EXPECTED_USED_LEN {' \
    <<<"$completion_validator" | cut -d: -f1)
response_status_line=$(grep -nF 'let response = request_buffers.response.status();' \
    <<<"$completion_validator" | cut -d: -f1)
[[ -n $used_length_line && -n $response_status_line \
    && $used_length_line -lt $response_status_line ]] \
    || fail 'completion reads device status before validating the complete output length'

reset_tombstone_impl=$(rust_block '^impl ProductionResetTombstone [{]' "$production") \
    || fail 'cannot isolate production reset tombstone actor'
reset_probe=$(rust_block '^    pub fn probe_ack_once' "$production") \
    || fail 'cannot isolate one-step reset acknowledgement probe'
for required in \
    'pub fn probe_ack_once(mut self, root: &mut Root) -> Result<ProductionResetAck, Self>' \
    'if self.inject_pending_once {' \
    'self.inject_pending_once = false;' \
    'if !self.reset_status_acknowledged() {' \
    'Ok(self.finalize_acknowledged_reset(root))'; do
    grep -Fq "$required" <<<"$reset_probe" \
        || fail "one-step reset acknowledgement lacks: $required"
done
probe_owner_returns=$(grep -F -c 'return Err(self);' <<<"$reset_probe" || true)
[[ $probe_owner_returns == 2 ]] \
    || fail 'one-step reset acknowledgement does not return its tombstone on every pending path'
probe_status_calls=$(grep -F -c 'self.reset_status_acknowledged()' <<<"$reset_probe" || true)
[[ $probe_status_calls == 1 ]] \
    || fail 'one-step reset acknowledgement can observe status more than once'
if grep -Eq '(for |while |loop |spin_loop|get_status|disable_bus_master|ack_interrupt|acknowledge_device_reset|abandon_queue_after_reset|seal_queue_retirement|ManuallyDrop::take|\.take\(\))' \
    <<<"$reset_probe"; then
    fail 'one-step reset acknowledgement gained polling or a second reset-finalization path'
fi

reset_retry=$(rust_block '^    pub fn retry_ack' "$production") \
    || fail 'cannot isolate bounded reset acknowledgement retry'
for required in \
    'pub fn retry_ack(mut self, root: &mut Root) -> Result<ProductionResetAck, Self>' \
    'if self.inject_pending_once {' \
    'self.inject_pending_once = false;' \
    'for _ in 0..POLL_LIMIT {' \
    'if self.reset_status_acknowledged() {' \
    'return Ok(self.finalize_acknowledged_reset(root));' \
    'spin_loop();' \
    'Err(self)'; do
    grep -Fq "$required" <<<"$reset_retry" \
        || fail "bounded reset acknowledgement behavior lacks: $required"
done
if grep -Eq '(get_status|disable_bus_master|ack_interrupt|acknowledge_device_reset|abandon_queue_after_reset|seal_queue_retirement|ManuallyDrop::take|\.take\(\))' \
    <<<"$reset_retry"; then
    fail 'bounded reset retry forked status observation or reset finalization'
fi

reset_status=$(rust_block '^    fn reset_status_acknowledged' "$production") \
    || fail 'cannot isolate unique reset-status observation'
for required in \
    '.expect("retained transport")' \
    '.get_status()' \
    '== DeviceStatus::empty()'; do
    grep -Fq "$required" <<<"$reset_status" \
        || fail "reset-status observation lacks: $required"
done
status_read_count=$(grep -F -c '.get_status()' <<<"$reset_tombstone_impl" || true)
[[ $status_read_count == 1 ]] \
    || fail "reset tombstone forked status observation (count=$status_read_count)"
if grep -Eq '(for |while |loop |spin_loop|\.set_status|ack_interrupt|disable_bus_master)' \
    <<<"$reset_status"; then
    fail 'reset-status observation gained polling or mutation'
fi

reset_finalize=$(rust_block '^    fn finalize_acknowledged_reset' "$production") \
    || fail 'cannot isolate unique reset acknowledgement finalization'
for required in \
    '-> ProductionResetAck' \
    'pci::disable_bus_master(root, self.session.device_function);' \
    '.ack_interrupt();' \
    'let generation = self.session.identity.device_generation;' \
    'dma::acknowledge_device_reset(generation)' \
    'ManuallyDrop::take(&mut self.session)' \
    'let queue = session.queue.take().expect("retained queue");' \
    'abandon_queue_after_reset(queue)' \
    'dma::seal_queue_retirement(reset)' \
    'drop(session.transport.take().expect("retained transport"));' \
    'pci::release_transport_claims()' \
    'assert_eq!(dma::retained_pages(generation), 3);' \
    'ProductionResetAck {'; do
    grep -Fq -- "$required" <<<"$reset_finalize" \
        || fail "reset acknowledgement finalization lacks: $required"
done
if grep -Eq '(Result<|for [^ ]+ in |while |loop |spin_loop|get_status)' \
    <<<"$reset_finalize"; then
    fail 'ready reset finalization regained polling or a fallible result'
fi
for unique_step in \
    'pci::disable_bus_master(root, self.session.device_function);' \
    '.ack_interrupt();' \
    'dma::acknowledge_device_reset(generation)' \
    'abandon_queue_after_reset(queue)' \
    'dma::seal_queue_retirement(reset)' \
    'pci::release_transport_claims()'; do
    step_count=$(grep -F -c "$unique_step" <<<"$reset_tombstone_impl" || true)
    [[ $step_count == 1 ]] \
        || fail "reset tombstone duplicated finalization step: $unique_step (count=$step_count)"
done

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
    CompletionFailure CompletionMode CompletionProbeProgress CompletionProgress FailedCompletion \
    HardwareIntentError HardwareIntentFailure PreparedCancelIntent PreparedPublishedResetIntent \
    PreparedRequestResetIntent \
    InterruptCause \
    InterruptCompletionProgress InterruptNotReadyReason InterruptReceipt \
    NotificationDisposition PendingCompletion PrepareReadError \
    PreparedGenerationAdvance PreparedQuiescenceApply PublishIdentityError QuiescenceApplyError \
    ResetGenerationError IntxRoute IntxTransitionError IntxTransitionFailure \
    MaskedIntx UnmaskedIntx; do
    grep -Fq "$export" "$lib" || fail "public facade omits $export"
done

echo 'production VirtIO substrate: PASS authority=registry-external identity=descriptive+reconstructible physical_owner=one-bdf+one-active-session intx=descriptive-route+linear-owner-epoch+masked-unmasked preparation=polling+irq+shared-result+full-unexposed-rollback+sequence-atomic linear_owner=non-clone+fail-closed preflight=failure-atomic publication=infallible+post-release-moves-only hardware_intent=real-owner+non-clone+failure-returns-owner+infallible-reset+completion-state-pop-aware notification=kick-or-suppressed+replay-safe completion=polling+irq+one-step-actor+one-validator+exact-used-length+pending-or-failed-resettable+pop-state reset_ack=one-step-actor+bounded-retry+unique-finalize cancel=exact-buffers generation=prevalidate+infallible-apply quiescence=prevalidate+infallible-apply legacy_portal=retained'
