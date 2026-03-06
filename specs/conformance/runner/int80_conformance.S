.section .text.axle_userprog, "ax"
.global axle_user_prog_start
.global axle_user_prog_end
axle_user_prog_start:
	// rbx = shared base (USER_SHARED_VA)
	movabs $0x0000000100008000, %rbx
// r12 = t0_ns baseline provided by the kernel (slot 511)
mov 8*511(%rbx), %r12

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
lea 0x680(%rbx), %rsi
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
lea 0x688(%rbx), %rsi
xorl %edi, %edi
movabs $3, %rax
int $0x80
mov 0x688(%rbx), %rcx
mov %rcx, 8*35(%rbx)

// port_wait(null out) with valid port
mov 0x688(%rbx), %rdi
xor %rsi, %rsi
xor %rdx, %rdx
movabs $5, %rax
int $0x80
mov %rax, 8*6(%rbx)

// port_wait(empty) with valid out
mov 0x688(%rbx), %rdi
xor %rsi, %rsi
lea 0x300(%rbx), %rdx
movabs $5, %rax
int $0x80
mov %rax, 8*7(%rbx)

// port_queue(null pkt)
mov 0x688(%rbx), %rdi
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

mov 0x688(%rbx), %rdi
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
mov 0x688(%rbx), %rdi
movabs $4, %rax
int $0x80
mov %rax, 8*10(%rbx)

// port_wait(roundtrip) rx_packet @ 0x480
lea 0x480(%rbx), %rdx
mov 0x688(%rbx), %rdi
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
lea 0x690(%rbx), %rdx
movl $1, %edi
movl $0, %esi                // ZX_CLOCK_MONOTONIC
movabs $6, %rax
int $0x80
mov %rax, 8*12(%rbx)

// timer_create(bad clock)
lea 0x690(%rbx), %rdx
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
lea 0x698(%rbx), %rdx
xorl %edi, %edi
xorl %esi, %esi
movabs $6, %rax
int $0x80
mov 0x698(%rbx), %rcx
mov %rcx, 8*36(%rbx)

// vmo_create(bad opts=1)
lea 0x6d0(%rbx), %rdx
movabs $0x1000, %rdi
movl $1, %esi
movabs $9, %rax
int $0x80
mov %rax, 8*63(%rbx)

// vmo_create(null out)
movabs $0x1000, %rdi
xorl %esi, %esi
xorl %edx, %edx
movabs $9, %rax
int $0x80
mov %rax, 8*64(%rbx)

// vmo_create(ok, out=&vmo_h)
lea 0x6d0(%rbx), %rdx
movabs $0x1000, %rdi
xorl %esi, %esi
movabs $9, %rax
int $0x80
mov %rax, 8*65(%rbx)
mov 0x6d0(%rbx), %rcx
mov %rcx, 8*66(%rbx)

// vmar_map(wrong type: vmar=timer_h)
mov 0x698(%rbx), %rdi
movl $0x403, %esi          // ZX_VM_SPECIFIC | READ | WRITE
movabs $0x10000, %rdx
mov 0x6d0(%rbx), %r10
xor %r8, %r8
movabs $0x1000, %r9
lea 0x6d8(%rbx), %rax
sub $8, %rsp
mov %rax, (%rsp)
movabs $10, %rax
int $0x80
add $8, %rsp
mov %rax, 8*67(%rbx)

// vmar_map(bad options: missing ZX_VM_SPECIFIC)
mov 8*62(%rbx), %rdi
movl $0x3, %esi            // READ | WRITE without SPECIFIC
movabs $0x10000, %rdx
mov 0x6d0(%rbx), %r10
xor %r8, %r8
movabs $0x1000, %r9
lea 0x6d8(%rbx), %rax
sub $8, %rsp
mov %rax, (%rsp)
movabs $10, %rax
int $0x80
add $8, %rsp
mov %rax, 8*68(%rbx)

// vmar_map(ok) -> mapped_addr at 0x6d8
mov 8*62(%rbx), %rdi
movl $0x403, %esi
movabs $0x10000, %rdx
mov 0x6d0(%rbx), %r10
xor %r8, %r8
movabs $0x1000, %r9
lea 0x6d8(%rbx), %rax
sub $8, %rsp
mov %rax, (%rsp)
movabs $10, %rax
int $0x80
add $8, %rsp
mov %rax, 8*69(%rbx)
mov 0x6d8(%rbx), %rax
mov %rax, 8*70(%rbx)

// Write/read through the mapped page.
movabs $0x0000000100010000, %r13
movabs $0x1122334455667788, %rax
mov %rax, (%r13)
mov (%r13), %rcx
movq $0, 8*71(%rbx)
cmp %rax, %rcx
jne vmar_write_check_done
movq $1, 8*71(%rbx)
vmar_write_check_done:

// vmar_map(overlap same address)
mov 8*62(%rbx), %rdi
movl $0x403, %esi
movabs $0x10000, %rdx
mov 0x6d0(%rbx), %r10
xor %r8, %r8
movabs $0x1000, %r9
lea 0x6e0(%rbx), %rax
sub $8, %rsp
mov %rax, (%rsp)
movabs $10, %rax
int $0x80
add $8, %rsp
mov %rax, 8*72(%rbx)

// vmar_protect(read-only)
mov 8*62(%rbx), %rdi
movl $0x1, %esi            // READ
movabs $0x0000000100010000, %rdx
movabs $0x1000, %r10
movabs $12, %rax
int $0x80
mov %rax, 8*73(%rbx)

// vmar_protect(read-write again)
mov 8*62(%rbx), %rdi
movl $0x3, %esi            // READ | WRITE
movabs $0x0000000100010000, %rdx
movabs $0x1000, %r10
movabs $12, %rax
int $0x80
mov %rax, 8*74(%rbx)

// vmar_unmap
mov 8*62(%rbx), %rdi
movabs $0x0000000100010000, %rsi
movabs $0x1000, %rdx
movabs $11, %rax
int $0x80
mov %rax, 8*75(%rbx)

	// vmar_map(remap after unmap)
	mov 8*62(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x10000, %rdx
mov 0x6d0(%rbx), %r10
xor %r8, %r8
movabs $0x1000, %r9
lea 0x6e0(%rbx), %rax
sub $8, %rsp
mov %rax, (%rsp)
movabs $10, %rax
int $0x80
	add $8, %rsp
	mov %rax, 8*76(%rbx)

	// channel_create(bad opts=1)
	lea 0x700(%rbx), %rsi
	lea 0x708(%rbx), %rdx
	movl $1, %edi
	movabs $13, %rax
	int $0x80
	mov %rax, 8*77(%rbx)

	// channel_create(null out0)
	xorl %edi, %edi
	xorl %esi, %esi
	lea 0x708(%rbx), %rdx
	movabs $13, %rax
	int $0x80
	mov %rax, 8*78(%rbx)

	// channel_create(null out1)
	xorl %edi, %edi
	lea 0x700(%rbx), %rsi
	xorl %edx, %edx
	movabs $13, %rax
	int $0x80
	mov %rax, 8*79(%rbx)

	// channel_create(ok)
	lea 0x700(%rbx), %rsi
	lea 0x708(%rbx), %rdx
	xorl %edi, %edi
	movabs $13, %rax
	int $0x80
	mov %rax, 8*80(%rbx)
	mov 0x700(%rbx), %rcx
	mov %rcx, 8*81(%rbx)
	mov 0x708(%rbx), %rcx
	mov %rcx, 8*82(%rbx)

	// channel_read(empty)
	mov 0x708(%rbx), %rdi
	xorl %esi, %esi
	lea 0x740(%rbx), %rdx
	xorl %r10d, %r10d
	movl $16, %r8d
	xorl %r9d, %r9d
	lea 0x758(%rbx), %rax
	lea 0x760(%rbx), %rcx
	sub $16, %rsp
	mov %rax, 0(%rsp)
	mov %rcx, 8(%rsp)
	movabs $15, %rax
	int $0x80
	add $16, %rsp
	mov %rax, 8*83(%rbx)

	// tx bytes @ 0x720
	movabs $0x1122334455667788, %rax
	mov %rax, 0x720(%rbx)
	movabs $0x8877665544332211, %rax
	mov %rax, 0x728(%rbx)

	// channel_write(h0 -> h1)
	mov 0x700(%rbx), %rdi
	xorl %esi, %esi
	lea 0x720(%rbx), %rdx
	movl $16, %r10d
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $14, %rax
	int $0x80
	mov %rax, 8*84(%rbx)

	// wait_one(h1, CHANNEL_READABLE)
	lea 0x768(%rbx), %r10
	movq $0, 0x768(%rbx)
	mov 0x708(%rbx), %rdi
	movl $0x1, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*85(%rbx)
	movq $0, 8*86(%rbx)
	mov 0x768(%rbx), %rax
	test $0x1, %rax
	jz channel_wait_readable_done
	movq $1, 8*86(%rbx)
channel_wait_readable_done:

	// channel_read(h1)
	movq $0, 0x758(%rbx)
	movq $0, 0x760(%rbx)
	mov 0x708(%rbx), %rdi
	xorl %esi, %esi
	lea 0x740(%rbx), %rdx
	xorl %r10d, %r10d
	movl $16, %r8d
	xorl %r9d, %r9d
	lea 0x758(%rbx), %rax
	lea 0x760(%rbx), %rcx
	sub $16, %rsp
	mov %rax, 0(%rsp)
	mov %rcx, 8(%rsp)
	movabs $15, %rax
	int $0x80
	add $16, %rsp
	mov %rax, 8*87(%rbx)
	mov 0x758(%rbx), %rax
	mov %rax, 8*88(%rbx)
	mov 0x760(%rbx), %rax
	mov %rax, 8*89(%rbx)
	movq $0, 8*90(%rbx)
	lea 0x720(%rbx), %rsi
	lea 0x740(%rbx), %rdi
	mov $2, %rcx
channel_compare_loop:
	mov (%rsi), %r8
	mov (%rdi), %r9
	cmp %r8, %r9
	jne channel_compare_done
	add $8, %rsi
	add $8, %rdi
	loop channel_compare_loop
	movq $1, 8*90(%rbx)
channel_compare_done:

	// close peer h0
	mov 0x700(%rbx), %rdi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*91(%rbx)

	// channel_write(peer closed on h1)
	mov 0x708(%rbx), %rdi
	xorl %esi, %esi
	lea 0x720(%rbx), %rdx
	movl $16, %r10d
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $14, %rax
	int $0x80
	mov %rax, 8*92(%rbx)

	// channel_read(peer closed on empty h1)
	movq $0, 0x758(%rbx)
	movq $0, 0x760(%rbx)
	mov 0x708(%rbx), %rdi
	xorl %esi, %esi
	lea 0x740(%rbx), %rdx
	xorl %r10d, %r10d
	movl $16, %r8d
	xorl %r9d, %r9d
	lea 0x758(%rbx), %rax
	lea 0x760(%rbx), %rcx
	sub $16, %rsp
	mov %rax, 0(%rsp)
	mov %rcx, 8(%rsp)
	movabs $15, %rax
	int $0x80
	add $16, %rsp
	mov %rax, 8*93(%rbx)

	// wait_one(h1, CHANNEL_PEER_CLOSED)
	lea 0x770(%rbx), %r10
	movq $0, 0x770(%rbx)
	mov 0x708(%rbx), %rdi
	movl $0x4, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*94(%rbx)
	mov 0x770(%rbx), %rax
	mov %rax, 8*95(%rbx)

	// eventpair_create(bad opts=1)
	lea 0x780(%rbx), %rsi
	lea 0x788(%rbx), %rdx
	movl $1, %edi
	movabs $16, %rax
	int $0x80
	mov %rax, 8*96(%rbx)

	// eventpair_create(null out0)
	xorl %edi, %edi
	xorl %esi, %esi
	lea 0x788(%rbx), %rdx
	movabs $16, %rax
	int $0x80
	mov %rax, 8*97(%rbx)

	// eventpair_create(null out1)
	xorl %edi, %edi
	lea 0x780(%rbx), %rsi
	xorl %edx, %edx
	movabs $16, %rax
	int $0x80
	mov %rax, 8*98(%rbx)

	// eventpair_create(ok)
	lea 0x780(%rbx), %rsi
	lea 0x788(%rbx), %rdx
	xorl %edi, %edi
	movabs $16, %rax
	int $0x80
	mov %rax, 8*99(%rbx)
	mov 0x780(%rbx), %rcx
	mov %rcx, 8*100(%rbx)
	mov 0x788(%rbx), %rcx
	mov %rcx, 8*101(%rbx)

	// object_signal_peer(bad mask: PEER_CLOSED)
	mov 0x780(%rbx), %rdi
	movl $0x4, %esi
	xorl %edx, %edx
	movabs $17, %rax
	int $0x80
	mov %rax, 8*102(%rbx)

	// object_signal_peer(set USER_SIGNAL_0 on peer)
	mov 0x780(%rbx), %rdi
	xorl %esi, %esi
	movl $0x01000000, %edx
	movabs $17, %rax
	int $0x80
	mov %rax, 8*103(%rbx)

	// wait_one(h1, USER_SIGNAL_0)
	lea 0x790(%rbx), %r10
	movq $0, 0x790(%rbx)
	mov 0x788(%rbx), %rdi
	movl $0x01000000, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*104(%rbx)
	mov 0x790(%rbx), %rax
	mov %rax, 8*105(%rbx)

	// close peer h0
	mov 0x780(%rbx), %rdi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*106(%rbx)

	// wait_one(h1, OBJECT_PEER_CLOSED)
	lea 0x798(%rbx), %r10
	movq $0, 0x798(%rbx)
	mov 0x788(%rbx), %rdi
	movl $0x4, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*107(%rbx)
	mov 0x798(%rbx), %rax
	mov %rax, 8*108(%rbx)

	// port_wait(wrong type: handle=timer_h)
	mov 0x698(%rbx), %rdi
	xor %rsi, %rsi
lea 0x300(%rbx), %rdx
movabs $5, %rax
int $0x80
mov %rax, 8*15(%rbx)

// port_queue(wrong type: port=timer_h)
mov 0x698(%rbx), %rdi
lea 0x440(%rbx), %rsi
movabs $4, %rax
int $0x80
mov %rax, 8*16(%rbx)

// timer_set(wrong type: handle=port_h)
mov 0x688(%rbx), %rdi
movabs $123456, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80
mov %rax, 8*17(%rbx)

// timer_cancel(wrong type: handle=port_h)
mov 0x688(%rbx), %rdi
movabs $8, %rax
int $0x80
mov %rax, 8*18(%rbx)

// object_wait_one(timer, TIMER_SIGNALED, deadline=0, observed=&obs0)
lea 0x6a0(%rbx), %rcx
movq $0, (%rcx)
mov 0x698(%rbx), %rdi
movl $0x8, %esi              // ZX_TIMER_SIGNALED
xor %rdx, %rdx
mov %rcx, %r10
movabs $1, %rax
int $0x80
mov %rax, 8*19(%rbx)
mov (%rcx), %rax
mov %rax, 8*20(%rbx)

// object_wait_async(timer, port, key=0x1234, signals=TIMER_SIGNALED, options=0)
mov 0x698(%rbx), %rdi
mov 0x688(%rbx), %rsi
movabs $0x1234, %rdx
movl $0x8, %r10d
xorl %r8d, %r8d
movabs $2, %rax
int $0x80
mov %rax, 8*21(%rbx)

// timer_set_immediate(deadline=0)
mov 0x698(%rbx), %rdi
xor %rsi, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80
mov %rax, 8*22(%rbx)

// port_wait(signal packet) @ 0x4c0
lea 0x4c0(%rbx), %rdx
mov 0x688(%rbx), %rdi
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
lea 0x6a8(%rbx), %rcx
movq $0, (%rcx)
mov 0x698(%rbx), %rdi
movl $0x8, %esi
xor %rdx, %rdx
mov %rcx, %r10
movabs $1, %rax
int $0x80
mov %rax, 8*27(%rbx)
mov (%rcx), %rax
mov %rax, 8*28(%rbx)

// object_wait_async invalid options: TIMESTAMP | BOOT_TIMESTAMP => INVALID_ARGS
mov 0x698(%rbx), %rdi
mov 0x688(%rbx), %rsi
movabs $0x2000, %rdx
movl $0x8, %r10d
movl $0x5, %r8d
movabs $2, %rax
int $0x80
mov %rax, 8*41(%rbx)

// timer_cancel to clear SIGNALED before timestamped wait_async
mov 0x698(%rbx), %rdi
movabs $8, %rax
int $0x80

// object_wait_async(timer, port, key=0x2001, options=TIMESTAMP)
mov 0x698(%rbx), %rdi
mov 0x688(%rbx), %rsi
movabs $0x2001, %rdx
movl $0x8, %r10d
movl $0x1, %r8d
movabs $2, %rax
int $0x80
mov %rax, 8*42(%rbx)

// timer_set_immediate(deadline=0) for monotonic timestamp packet
mov 0x698(%rbx), %rdi
xor %rsi, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80

// port_wait(monotonic timestamp signal packet) @ 0x500
lea 0x500(%rbx), %rdx
mov 0x688(%rbx), %rdi
xor %rsi, %rsi
movabs $5, %rax
int $0x80
mov %rax, 8*43(%rbx)
mov 0x520(%rbx), %rax
mov %rax, 8*44(%rbx)
movq $0, 8*45(%rbx)
test %rax, %rax
jz wait_async_ts_done
cmp %r12, %rax
jb wait_async_ts_done
movq $1, 8*45(%rbx)
wait_async_ts_done:

// timer_cancel again to clear SIGNALED before boot-timestamped wait_async
mov 0x698(%rbx), %rdi
movabs $8, %rax
int $0x80

// object_wait_async(timer, port, key=0x2002, options=BOOT_TIMESTAMP)
mov 0x698(%rbx), %rdi
mov 0x688(%rbx), %rsi
movabs $0x2002, %rdx
movl $0x8, %r10d
movl $0x4, %r8d
movabs $2, %rax
int $0x80
mov %rax, 8*46(%rbx)

// timer_set_immediate(deadline=0) for boot timestamp packet
mov 0x698(%rbx), %rdi
xor %rsi, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80

// port_wait(boot timestamp signal packet) @ 0x540
lea 0x540(%rbx), %rdx
mov 0x688(%rbx), %rdi
xor %rsi, %rsi
movabs $5, %rax
int $0x80
mov %rax, 8*47(%rbx)
mov 0x560(%rbx), %rax
mov %rax, 8*48(%rbx)
movq $0, 8*49(%rbx)
test %rax, %rax
jz wait_async_boot_done
cmp %r12, %rax
jb wait_async_boot_done
movq $1, 8*49(%rbx)
wait_async_boot_done:

// EDGE wait on already-signaled timer must not queue immediately.
mov 0x698(%rbx), %rdi
mov 0x688(%rbx), %rsi
movabs $0x2222, %rdx
movl $0x8, %r10d
movl $0x2, %r8d
movabs $2, %rax
int $0x80
mov %rax, 8*50(%rbx)

// port_wait(non-blocking) should report SHOULD_WAIT because no edge transition happened yet.
lea 0x580(%rbx), %rdx
mov 0x688(%rbx), %rdi
xor %rsi, %rsi
movabs $5, %rax
int $0x80
mov %rax, 8*51(%rbx)

// Clear then re-signal timer so the EDGE observer sees a false->true transition.
mov 0x698(%rbx), %rdi
movabs $8, %rax
int $0x80

mov 0x698(%rbx), %rdi
xor %rsi, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80

lea 0x580(%rbx), %rdx
mov 0x688(%rbx), %rdi
xor %rsi, %rsi
movabs $5, %rax
int $0x80
mov %rax, 8*52(%rbx)
mov 0x580(%rbx), %rax
mov %rax, 8*53(%rbx)

// timer_set(deadline=t0+500ms)
mov 0x698(%rbx), %rdi
mov %r12, %rsi
add $500000000, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80
mov %rax, 8*29(%rbx)

// object_wait_one(timer, TIMER_SIGNALED, deadline=t0+200ms, observed=&obs2) should time out
lea 0x6b0(%rbx), %rcx
movq $0, (%rcx)
mov 0x698(%rbx), %rdi
movl $0x8, %esi
mov %r12, %rdx
add $200000000, %rdx
mov %rcx, %r10
movabs $1, %rax
int $0x80
mov %rax, 8*37(%rbx)
mov (%rcx), %rax
mov %rax, 8*38(%rbx)

// object_wait_one(timer, TIMER_SIGNALED, deadline=t0+500ms, observed=&obs3) should be OK
lea 0x6b8(%rbx), %rcx
movq $0, (%rcx)
mov 0x698(%rbx), %rdi
movl $0x8, %esi
mov %r12, %rdx
add $500000000, %rdx
mov %rcx, %r10
movabs $1, %rax
int $0x80
mov %rax, 8*39(%rbx)
mov (%rcx), %rax
mov %rax, 8*40(%rbx)

// --- Port reserve test ----------------------------------------------------

// port_create(ok, out=&reserve_port_h)
lea 0x6c0(%rbx), %rsi
xorl %edi, %edi
movabs $3, %rax
int $0x80

// Fill user quota until port_queue returns SHOULD_WAIT.
xor %r13, %r13
reserve_fill_loop:
mov 0x6c0(%rbx), %rdi
lea 0x440(%rbx), %rsi
movabs $4, %rax
int $0x80
test %rax, %rax
jne reserve_fill_done
inc %r13
jmp reserve_fill_loop
reserve_fill_done:
mov %rax, 8*54(%rbx)

// Timer is currently signaled; wait_async should enqueue into reserved slots.
mov 0x698(%rbx), %rdi
mov 0x6c0(%rbx), %rsi
movabs $0x3001, %rdx
movl $0x8, %r10d
xorl %r8d, %r8d
movabs $2, %rax
int $0x80
mov %rax, 8*55(%rbx)

movq $0, 8*56(%rbx)
movq $0, 8*57(%rbx)
xor %r14, %r14
reserve_drain_loop:
mov 0x6c0(%rbx), %rdi
xor %rsi, %rsi
lea 0x5c0(%rbx), %rdx
movabs $5, %rax
int $0x80
test %rax, %rax
jne reserve_drain_done
mov 0x5c8(%rbx), %eax
cmp $1, %eax
jne reserve_drain_next
mov 0x5c0(%rbx), %rcx
cmp $0x3001, %rcx
jne reserve_drain_next
mov %rax, 8*57(%rbx)
cmp %r13, %r14
jne reserve_drain_done
movq $1, 8*56(%rbx)
jmp reserve_drain_done
reserve_drain_next:
inc %r14
jmp reserve_drain_loop
reserve_drain_done:

// --- Port pending-merge test ----------------------------------------------

// port_create(ok, out=&pending_port_h)
lea 0x6c8(%rbx), %rsi
xorl %edi, %edi
movabs $3, %rax
int $0x80

// Fill user quota on the pending port.
pending_fill_user_loop:
mov 0x6c8(%rbx), %rdi
lea 0x440(%rbx), %rsi
movabs $4, %rax
int $0x80
test %rax, %rax
jne pending_fill_user_done
jmp pending_fill_user_loop
pending_fill_user_done:

// Fill the reserved region with immediate signal packets (PORT_KERNEL_RESERVE = 16).
xor %r14, %r14
pending_fill_kernel_loop:
cmp $16, %r14
je pending_fill_kernel_done
mov 0x698(%rbx), %rdi
mov 0x6c8(%rbx), %rsi
movabs $0x4100, %rdx
add %r14, %rdx
movl $0x8, %r10d
xorl %r8d, %r8d
movabs $2, %rax
int $0x80
inc %r14
jmp pending_fill_kernel_loop
pending_fill_kernel_done:

// One more observer becomes pending because the queue is full.
mov 0x698(%rbx), %rdi
mov 0x6c8(%rbx), %rsi
movabs $0x5000, %rdx
movl $0x8, %r10d
xorl %r8d, %r8d
movabs $2, %rax
int $0x80
mov %rax, 8*58(%rbx)

// Toggle the timer twice while the queue stays full; pending count should merge to 3 total.
mov 0x698(%rbx), %rdi
movabs $8, %rax
int $0x80
mov 0x698(%rbx), %rdi
xor %rsi, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80
mov 0x698(%rbx), %rdi
movabs $8, %rax
int $0x80
mov 0x698(%rbx), %rdi
xor %rsi, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80

// Pop one packet so the pending signal can flush into the freed slot.
mov 0x6c8(%rbx), %rdi
xor %rsi, %rsi
lea 0x600(%rbx), %rdx
movabs $5, %rax
int $0x80

movq $0, 8*59(%rbx)
movq $0, 8*60(%rbx)
movq $0, 8*61(%rbx)
pending_drain_loop:
mov 0x6c8(%rbx), %rdi
xor %rsi, %rsi
lea 0x600(%rbx), %rdx
movabs $5, %rax
int $0x80
mov %rax, 8*59(%rbx)
test %rax, %rax
jne pending_drain_done
mov 0x600(%rbx), %rcx
cmp $0x5000, %rcx
jne pending_drain_loop
mov 0x618(%rbx), %rax
mov %rax, 8*60(%rbx)
cmp $3, %rax
jne pending_drain_done
mov 0x608(%rbx), %eax
cmp $1, %eax
jne pending_drain_done
movq $1, 8*61(%rbx)
pending_drain_done:

// timer_cancel
mov 0x698(%rbx), %rdi
movabs $8, %rax
int $0x80
mov %rax, 8*30(%rbx)

// timer_close
mov 0x698(%rbx), %rdi
movabs $0, %rax
int $0x80
mov %rax, 8*31(%rbx)

// timer_close_again
mov 0x698(%rbx), %rdi
movabs $0, %rax
int $0x80
mov %rax, 8*32(%rbx)

// handle_close(port_h)
mov 0x688(%rbx), %rdi
movabs $0, %rax
int $0x80
mov %rax, 8*33(%rbx)

// handle_close_again(port_h)
mov 0x688(%rbx), %rdi
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
