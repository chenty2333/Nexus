use axle_arch_x86_64::debug_break;

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const SLOT_SMP_SMOKE_PRESENT: usize = 1008;
const SLOT_SMP_SMOKE_STATUS: usize = 1009;

const STATUS_OK: u64 = 0;
const STATUS_PANIC: u64 = u64::MAX;

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start() -> ! {
    write_slot(SLOT_SMP_SMOKE_PRESENT, 1);
    write_slot(SLOT_SMP_SMOKE_STATUS, STATUS_OK);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_SMP_SMOKE_PRESENT, 1);
    write_slot(SLOT_SMP_SMOKE_STATUS, STATUS_PANIC);
    debug_break()
}

fn write_slot(index: usize, value: u64) {
    // SAFETY: the bootstrap runner ABI reserves the shared two-page slot window at
    // USER_SHARED_BASE. This smoke only writes within fixed slot indices owned by
    // the kernel/userspace bootstrap contract.
    unsafe {
        *((USER_SHARED_BASE as *mut u64).add(index)) = value;
    }
}
