//! Minimal ring3 bring-up for the userspace conformance runner.
//!
//! This is intentionally a bootstrap bridge:
//! - single address space (kernel + one userspace image mapped into same CR3)
//! - userspace calls syscalls via `int 0x80`
//! - userspace signals completion via `int3`
//!
//! The immediate purpose is to force correctness work in:
//! - copyin/copyout validation
//! - user pointer boundaries
//! - ring3 -> ring0 transitions (TSS/RSP0)

use x86_64::instructions::segmentation::Segment;

// --- Userspace virtual layout (in current single-address-space model) ---

const USER_REGION_BYTES: u64 = 0x3000;
const USER_CODE_VA: u64 = 0x0000_0001_0000_0000; // 4 GiB
const USER_SHARED_VA: u64 = USER_CODE_VA + 0x1000;
const USER_STACK_VA: u64 = USER_CODE_VA + 0x2000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;

// --- Shared summary slots (u64) written by userspace ---

const SLOT_OK: usize = 0;

// Match the existing kernel bring-up summary keys so `specs/conformance/scenarios/*.toml`
// don't need churn when we move execution from ring0 to ring3.
const SLOT_UNKNOWN: usize = 1;
const SLOT_CLOSE_INVALID: usize = 2;
const SLOT_PORT_CREATE_BAD_OPTS: usize = 3;
const SLOT_PORT_CREATE_NULL_OUT: usize = 4;
const SLOT_BAD_WAIT: usize = 5;
const SLOT_PORT_WAIT_NULL_OUT: usize = 6;
const SLOT_EMPTY_WAIT: usize = 7;
const SLOT_PORT_QUEUE_NULL_PKT: usize = 8;
const SLOT_PORT_QUEUE_BAD_TYPE: usize = 9;
const SLOT_QUEUE: usize = 10;
const SLOT_WAIT: usize = 11;
const SLOT_TIMER_CREATE_BAD_OPTS: usize = 12;
const SLOT_TIMER_CREATE_BAD_CLOCK: usize = 13;
const SLOT_TIMER_CREATE_NULL_OUT: usize = 14;
const SLOT_PORT_WAIT_WRONG_TYPE: usize = 15;
const SLOT_PORT_QUEUE_WRONG_TYPE: usize = 16;
const SLOT_TIMER_SET_WRONG_TYPE: usize = 17;
const SLOT_TIMER_CANCEL_WRONG_TYPE: usize = 18;
const SLOT_WAIT_ONE_UNSIGNALED: usize = 19;
const SLOT_WAIT_ONE_UNSIGNALED_OBS: usize = 20;
const SLOT_WAIT_ASYNC: usize = 21;
const SLOT_TIMER_SET_IMMEDIATE: usize = 22;
const SLOT_WAIT_SIGNAL: usize = 23;
const SLOT_SIGNAL_TRIGGER: usize = 24;
const SLOT_SIGNAL_OBSERVED: usize = 25;
const SLOT_SIGNAL_COUNT: usize = 26;
const SLOT_WAIT_ONE_SIGNALED: usize = 27;
const SLOT_WAIT_ONE_SIGNALED_OBS: usize = 28;
const SLOT_TIMER_SET: usize = 29;
const SLOT_TIMER_CANCEL: usize = 30;
const SLOT_TIMER_CLOSE: usize = 31;
const SLOT_TIMER_CLOSE_AGAIN: usize = 32;
const SLOT_CLOSE: usize = 33;
const SLOT_CLOSE_AGAIN: usize = 34;
const SLOT_PORT_H: usize = 35;
const SLOT_TIMER_H: usize = 36;

const SLOT_MAX: usize = SLOT_TIMER_H;

#[repr(align(4096))]
struct AlignedPage([u8; 4096]);
#[repr(align(4096))]
struct AlignedPageTable([u64; 512]);

static mut USER_CODE_PAGE: AlignedPage = AlignedPage([0; 4096]);
static mut USER_SHARED_PAGE: AlignedPage = AlignedPage([0; 4096]);
static mut USER_STACK_PAGE: AlignedPage = AlignedPage([0; 4096]);

static mut USER_PD: AlignedPageTable = AlignedPageTable([0; 512]);
static mut USER_PT: AlignedPageTable = AlignedPageTable([0; 512]);

// PVH boot page tables (identity-mapped, used as the active CR3).
unsafe extern "C" {
    static mut pvh_pml4: [u64; 512];
    static mut pvh_pdpt: [u64; 512];
}

// Page table flag bits (x86_64).
const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;

fn phys_of<T>(p: *const T) -> u64 {
    // In the current PVH identity mapping, physical == virtual for kernel static data.
    p as u64
}

fn map_userspace_pages() {
    // SAFETY: early bring-up is single-core; page table mutation is serialized.
    unsafe {
        let pml4 = core::ptr::addr_of_mut!(pvh_pml4).cast::<u64>();
        let pdpt = core::ptr::addr_of_mut!(pvh_pdpt).cast::<u64>();
        let user_pd = core::ptr::addr_of_mut!(USER_PD).cast::<u64>();
        let user_pt = core::ptr::addr_of_mut!(USER_PT).cast::<u64>();

        // Allow user mappings under PML4[0] by setting U=1 at the top level.
        *pml4.add(0) |= PTE_U;

        // Install PDPT[4] -> USER_PD (maps VA 4GiB..5GiB).
        *pdpt.add(4) = phys_of(core::ptr::addr_of!(USER_PD)) | (PTE_P | PTE_W | PTE_U);

        // USER_PD[0] -> USER_PT (maps VA 4GiB..4GiB+2MiB).
        *user_pd.add(0) = phys_of(core::ptr::addr_of!(USER_PT)) | (PTE_P | PTE_W | PTE_U);

        // Map the three user pages.
        *user_pt.add(0) = phys_of(core::ptr::addr_of!(USER_CODE_PAGE)) | (PTE_P | PTE_W | PTE_U);
        *user_pt.add(1) = phys_of(core::ptr::addr_of!(USER_SHARED_PAGE)) | (PTE_P | PTE_W | PTE_U);
        *user_pt.add(2) = phys_of(core::ptr::addr_of!(USER_STACK_PAGE)) | (PTE_P | PTE_W | PTE_U);

        // Flush TLB by reloading CR3.
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

unsafe extern "C" {
    static axle_user_prog_start: u8;
    static axle_user_prog_end: u8;
}

fn load_user_program() {
    // SAFETY: symbols are defined by `global_asm!` below and form a contiguous region.
    unsafe {
        let start = core::ptr::addr_of!(axle_user_prog_start);
        let end = core::ptr::addr_of!(axle_user_prog_end);
        let len = end.offset_from(start) as usize;
        let src = core::slice::from_raw_parts(start, len);

        if len > 4096 {
            panic!("userspace: program too large for one page (len={})", len);
        }

        let dst = core::ptr::addr_of_mut!(USER_CODE_PAGE).cast::<u8>();
        // Use `ptr::copy` (memmove semantics) to avoid relying on non-overlap
        // across toolchain/linker layouts during bring-up.
        core::ptr::copy(src.as_ptr(), dst, len);
        core::ptr::write_bytes(dst.add(len), 0, 4096 - len);
    }
}

/// Validate a user pointer for a copyin/copyout of `len` bytes.
///
/// Bring-up rule: pointers must be fully contained within the mapped shared page
/// or the mapped stack page (so the kernel never faults on bad pointers).
pub fn validate_user_ptr(ptr: u64, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    let len_u64 = len as u64;
    let end = match ptr.checked_add(len_u64) {
        Some(v) => v,
        None => return false,
    };

    let in_shared = ptr >= USER_SHARED_VA && end <= (USER_SHARED_VA + 0x1000);
    let in_stack = ptr >= USER_STACK_VA && end <= (USER_STACK_VA + 0x1000);
    in_shared || in_stack
}

fn shared_slots() -> &'static mut [u64] {
    // SAFETY: shared page is always mapped and 8-byte aligned; we only use it after mapping.
    unsafe { core::slice::from_raw_parts_mut(USER_SHARED_VA as *mut u64, 512) }
}

/// Called by the breakpoint handler to print the userspace-produced summary.
pub fn on_breakpoint() -> ! {
    let slots = shared_slots();
    if slots[SLOT_OK] != 1 {
        panic!("userspace: conformance reported failure (ok=0)");
    }

    crate::kprintln!(
        "kernel: int80 conformance ok (unknown={}, close_invalid={}, port_create_bad_opts={}, port_create_null_out={}, bad_wait={}, port_wait_null_out={}, empty_wait={}, port_queue_null_pkt={}, port_queue_bad_type={}, queue={}, wait={}, timer_create_bad_opts={}, timer_create_bad_clock={}, timer_create_null_out={}, port_wait_wrong_type={}, port_queue_wrong_type={}, timer_set_wrong_type={}, timer_cancel_wrong_type={}, wait_one_unsignaled={}, wait_one_unsignaled_observed={}, wait_async={}, timer_set_immediate={}, wait_signal={}, signal_trigger={}, signal_observed={}, signal_count={}, wait_one_signaled={}, wait_one_signaled_observed={}, timer_set={}, timer_cancel={}, timer_close={}, timer_close_again={}, close={}, close_again={}, port_h={}, timer_h={})",
        slots[SLOT_UNKNOWN] as i64,
        slots[SLOT_CLOSE_INVALID] as i64,
        slots[SLOT_PORT_CREATE_BAD_OPTS] as i64,
        slots[SLOT_PORT_CREATE_NULL_OUT] as i64,
        slots[SLOT_BAD_WAIT] as i64,
        slots[SLOT_PORT_WAIT_NULL_OUT] as i64,
        slots[SLOT_EMPTY_WAIT] as i64,
        slots[SLOT_PORT_QUEUE_NULL_PKT] as i64,
        slots[SLOT_PORT_QUEUE_BAD_TYPE] as i64,
        slots[SLOT_QUEUE] as i64,
        slots[SLOT_WAIT] as i64,
        slots[SLOT_TIMER_CREATE_BAD_OPTS] as i64,
        slots[SLOT_TIMER_CREATE_BAD_CLOCK] as i64,
        slots[SLOT_TIMER_CREATE_NULL_OUT] as i64,
        slots[SLOT_PORT_WAIT_WRONG_TYPE] as i64,
        slots[SLOT_PORT_QUEUE_WRONG_TYPE] as i64,
        slots[SLOT_TIMER_SET_WRONG_TYPE] as i64,
        slots[SLOT_TIMER_CANCEL_WRONG_TYPE] as i64,
        slots[SLOT_WAIT_ONE_UNSIGNALED] as i64,
        slots[SLOT_WAIT_ONE_UNSIGNALED_OBS] as i64,
        slots[SLOT_WAIT_ASYNC] as i64,
        slots[SLOT_TIMER_SET_IMMEDIATE] as i64,
        slots[SLOT_WAIT_SIGNAL] as i64,
        slots[SLOT_SIGNAL_TRIGGER] as i64,
        slots[SLOT_SIGNAL_OBSERVED] as i64,
        slots[SLOT_SIGNAL_COUNT],
        slots[SLOT_WAIT_ONE_SIGNALED] as i64,
        slots[SLOT_WAIT_ONE_SIGNALED_OBS] as i64,
        slots[SLOT_TIMER_SET] as i64,
        slots[SLOT_TIMER_CANCEL] as i64,
        slots[SLOT_TIMER_CLOSE] as i64,
        slots[SLOT_TIMER_CLOSE_AGAIN] as i64,
        slots[SLOT_CLOSE] as i64,
        slots[SLOT_CLOSE_AGAIN] as i64,
        slots[SLOT_PORT_H],
        slots[SLOT_TIMER_H]
    );

    crate::arch::cpu::halt_loop();
}

/// Enter ring3 and run the embedded userspace conformance program.
pub fn run() -> ! {
    map_userspace_pages();
    load_user_program();

    // Zero shared slots and set `ok=0` pessimistically.
    let slots = shared_slots();
    for i in 0..=SLOT_MAX {
        slots[i] = 0;
    }

    let selectors = crate::arch::gdt::init();

    // SAFETY: we build a valid iret frame to transition to ring3 using the installed GDT selectors.
    unsafe {
        use x86_64::instructions::segmentation::{DS, ES};

        DS::set_reg(selectors.user_data);
        ES::set_reg(selectors.user_data);

        let entry = USER_CODE_VA;
        let stack = USER_STACK_TOP;
        // Keep interrupts disabled during early bring-up. We only rely on software
        // traps (`int 0x80`, `int3`) and do not yet have handlers for hardware IRQs.
        let rflags: u64 = 0x002; // bit1 set, IF=0

        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) selectors.user_data.0 as u64,
            rsp = in(reg) stack,
            rflags = in(reg) rflags,
            cs = in(reg) selectors.user_code.0 as u64,
            rip = in(reg) entry,
            options(noreturn),
        );
    }
}

// --- Embedded userspace program (one page) ---

core::arch::global_asm!(
    r#"
    .section .text.axle_userprog, "ax"
    .global axle_user_prog_start
    .global axle_user_prog_end
axle_user_prog_start:
    // rbx = shared base (USER_SHARED_VA)
    movabs $0x0000000100001000, %rbx

    // Helper macro style:
    // - syscall nr in rax
    // - args in rdi,rsi,rdx,r10,r8,r9
    // - store rax (status) to [rbx + slot*8]

    // unknown syscall
    movabs $0xffffffffffffffff, %rax
    xor %rdi, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    xor %r8, %r8
    xor %r9, %r9
    int $0x80
    mov %rax, 8*1(%rbx)

    // handle_close(invalid=0)
    movabs $0, %rdi
    movabs $0, %rax
    int $0x80
    mov %rax, 8*2(%rbx)

    // port_create(bad opts=1, out=&ignored_handle)
    lea 0x200(%rbx), %rsi
    movl $1, %edi
    movabs $3, %rax
    int $0x80
    mov %rax, 8*3(%rbx)

    // port_create(null out)
    xorl %edi, %edi
    xorl %esi, %esi
    movabs $3, %rax
    int $0x80
    mov %rax, 8*4(%rbx)

    // port_wait(bad handle=0, out=&pkt)
    lea 0x300(%rbx), %rdx
    xor %rsi, %rsi
    xor %rdi, %rdi
    movabs $5, %rax
    int $0x80
    mov %rax, 8*5(%rbx)

    // port_create(ok, out=&port_h)
    lea 0x208(%rbx), %rsi
    xorl %edi, %edi
    movabs $3, %rax
    int $0x80
    mov 0x208(%rbx), %rcx
    mov %rcx, 8*35(%rbx)

    // port_wait(null out) with valid port
    mov 0x208(%rbx), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    movabs $5, %rax
    int $0x80
    mov %rax, 8*6(%rbx)

    // port_wait(empty) with valid out
    mov 0x208(%rbx), %rdi
    xor %rsi, %rsi
    lea 0x300(%rbx), %rdx
    movabs $5, %rax
    int $0x80
    mov %rax, 8*7(%rbx)

    // port_queue(null pkt)
    mov 0x208(%rbx), %rdi
    xor %rsi, %rsi
    movabs $4, %rax
    int $0x80
    mov %rax, 8*8(%rbx)

    // port_queue(bad type)
    // bad_type_packet @ 0x400
    lea 0x400(%rbx), %rsi
    movabs $0, %rax
    movabs $0, %rcx
    mov %rcx, 0x00(%rsi)         // key=0
    movl $1, 0x08(%rsi)          // type = ZX_PKT_TYPE_USER+1
    movl $0, 0x0c(%rsi)          // status
    // user payload zero
    movq $0, 0x10(%rsi)
    movq $0, 0x18(%rsi)
    movq $0, 0x20(%rsi)
    movq $0, 0x28(%rsi)

    mov 0x208(%rbx), %rdi
    movabs $4, %rax
    int $0x80
    mov %rax, 8*9(%rbx)

    // tx_packet @ 0x440
    lea 0x440(%rbx), %rsi
    movabs $0xAA55AA55AA55AA55, %rcx
    mov %rcx, 0x00(%rsi)         // key
    movl $0, 0x08(%rsi)          // type = USER
    movl $-123, 0x0c(%rsi)       // status
    movabs $0x11, %rcx
    mov %rcx, 0x10(%rsi)
    movabs $0x22, %rcx
    mov %rcx, 0x18(%rsi)
    movabs $0x33, %rcx
    mov %rcx, 0x20(%rsi)
    movabs $0x44, %rcx
    mov %rcx, 0x28(%rsi)

    // port_queue(ok)
    mov 0x208(%rbx), %rdi
    movabs $4, %rax
    int $0x80
    mov %rax, 8*10(%rbx)

    // port_wait(roundtrip) rx_packet @ 0x480
    lea 0x480(%rbx), %rdx
    mov 0x208(%rbx), %rdi
    xor %rsi, %rsi
    movabs $5, %rax
    int $0x80
    mov %rax, 8*11(%rbx)

    // Compare rx_packet vs tx_packet (6 qwords)
    lea 0x440(%rbx), %rsi
    lea 0x480(%rbx), %rdi
    mov $6, %rcx
1:
    mov (%rsi), %r8
    mov (%rdi), %r9
    cmp %r8, %r9
    jne user_fail
    add $8, %rsi
    add $8, %rdi
    loop 1b

    // timer_create(bad opts=1)
    lea 0x210(%rbx), %rdx
    movl $1, %edi
    movl $0, %esi                // ZX_CLOCK_MONOTONIC
    movabs $6, %rax
    int $0x80
    mov %rax, 8*12(%rbx)

    // timer_create(bad clock)
    lea 0x210(%rbx), %rdx
    xorl %edi, %edi
    movl $1, %esi
    movabs $6, %rax
    int $0x80
    mov %rax, 8*13(%rbx)

    // timer_create(null out)
    xorl %edi, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    movabs $6, %rax
    int $0x80
    mov %rax, 8*14(%rbx)

    // timer_create(ok, out=&timer_h)
    lea 0x218(%rbx), %rdx
    xorl %edi, %edi
    xorl %esi, %esi
    movabs $6, %rax
    int $0x80
    mov 0x218(%rbx), %rcx
    mov %rcx, 8*36(%rbx)

    // port_wait(wrong type: handle=timer_h)
    mov 0x218(%rbx), %rdi
    xor %rsi, %rsi
    lea 0x300(%rbx), %rdx
    movabs $5, %rax
    int $0x80
    mov %rax, 8*15(%rbx)

    // port_queue(wrong type: port=timer_h)
    mov 0x218(%rbx), %rdi
    lea 0x440(%rbx), %rsi
    movabs $4, %rax
    int $0x80
    mov %rax, 8*16(%rbx)

    // timer_set(wrong type: handle=port_h)
    mov 0x208(%rbx), %rdi
    movabs $123456, %rsi
    xor %rdx, %rdx
    movabs $7, %rax
    int $0x80
    mov %rax, 8*17(%rbx)

    // timer_cancel(wrong type: handle=port_h)
    mov 0x208(%rbx), %rdi
    movabs $8, %rax
    int $0x80
    mov %rax, 8*18(%rbx)

    // object_wait_one(timer, TIMER_SIGNALED, deadline=0, observed=&obs0)
    lea 0x220(%rbx), %rcx
    movq $0, (%rcx)
    mov 0x218(%rbx), %rdi
    movl $0x8, %esi              // ZX_TIMER_SIGNALED
    xor %rdx, %rdx
    mov %rcx, %r10
    movabs $1, %rax
    int $0x80
    mov %rax, 8*19(%rbx)
    mov (%rcx), %rax
    mov %rax, 8*20(%rbx)

    // object_wait_async(timer, port, key=0x1234, signals=TIMER_SIGNALED, options=0)
    mov 0x218(%rbx), %rdi
    mov 0x208(%rbx), %rsi
    movabs $0x1234, %rdx
    movl $0x8, %r10d
    xorl %r8d, %r8d
    movabs $2, %rax
    int $0x80
    mov %rax, 8*21(%rbx)

    // timer_set_immediate(deadline=0)
    mov 0x218(%rbx), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    movabs $7, %rax
    int $0x80
    mov %rax, 8*22(%rbx)

    // port_wait(signal packet) @ 0x4c0
    lea 0x4c0(%rbx), %rdx
    mov 0x208(%rbx), %rdi
    xor %rsi, %rsi
    movabs $5, %rax
    int $0x80
    mov %rax, 8*23(%rbx)

    // Extract trigger/observed/count from signal packet payload.
    // user.u64[0] at offset 0x10, count at 0x18
    mov 0x4d0(%rbx), %rax        // first payload word
    mov %eax, %ecx               // trigger (low 32)
    shr $32, %rax
    mov %eax, %edx               // observed (high 32)
    mov %rcx, 8*24(%rbx)
    mov %rdx, 8*25(%rbx)
    mov 0x4d8(%rbx), %rax        // count
    mov %rax, 8*26(%rbx)

    // object_wait_one(timer, TIMER_SIGNALED, observed=&obs1) should be OK
    lea 0x228(%rbx), %rcx
    movq $0, (%rcx)
    mov 0x218(%rbx), %rdi
    movl $0x8, %esi
    xor %rdx, %rdx
    mov %rcx, %r10
    movabs $1, %rax
    int $0x80
    mov %rax, 8*27(%rbx)
    mov (%rcx), %rax
    mov %rax, 8*28(%rbx)

    // timer_set(deadline=123456)
    mov 0x218(%rbx), %rdi
    movabs $123456, %rsi
    xor %rdx, %rdx
    movabs $7, %rax
    int $0x80
    mov %rax, 8*29(%rbx)

    // timer_cancel
    mov 0x218(%rbx), %rdi
    movabs $8, %rax
    int $0x80
    mov %rax, 8*30(%rbx)

    // timer_close
    mov 0x218(%rbx), %rdi
    movabs $0, %rax
    int $0x80
    mov %rax, 8*31(%rbx)

    // timer_close_again
    mov 0x218(%rbx), %rdi
    movabs $0, %rax
    int $0x80
    mov %rax, 8*32(%rbx)

    // handle_close(port_h)
    mov 0x208(%rbx), %rdi
    movabs $0, %rax
    int $0x80
    mov %rax, 8*33(%rbx)

    // handle_close_again(port_h)
    mov 0x208(%rbx), %rdi
    movabs $0, %rax
    int $0x80
    mov %rax, 8*34(%rbx)

    // ok=1
    movq $1, 0x00(%rbx)
    int3

user_fail:
    // ok=0 and exit via int3
    movq $0, 0x00(%rbx)
    int3

axle_user_prog_end:
    "#,
    options(att_syntax)
);

// Compile-time witness: slot indices must fit in one page of u64 slots.
const _: () = assert!(SLOT_MAX < 512);
