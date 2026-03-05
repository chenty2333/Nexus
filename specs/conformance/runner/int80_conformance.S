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

// object_wait_one(timer, TIMER_SIGNALED, deadline=123455, observed=&obs2) should time out
lea 0x230(%rbx), %rcx
movq $0, (%rcx)
mov 0x218(%rbx), %rdi
movl $0x8, %esi
movabs $123455, %rdx
mov %rcx, %r10
movabs $1, %rax
int $0x80
mov %rax, 8*37(%rbx)
mov (%rcx), %rax
mov %rax, 8*38(%rbx)

// object_wait_one(timer, TIMER_SIGNALED, deadline=123456, observed=&obs3) should be OK
lea 0x238(%rbx), %rcx
movq $0, (%rcx)
mov 0x218(%rbx), %rdi
movl $0x8, %esi
movabs $123456, %rdx
mov %rcx, %r10
movabs $1, %rax
int $0x80
mov %rax, 8*39(%rbx)
mov (%rcx), %rax
mov %rax, 8*40(%rbx)

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
