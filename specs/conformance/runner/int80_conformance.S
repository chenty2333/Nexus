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

	// vmar_allocate(wrong type: parent=timer_h)
	mov 0x698(%rbx), %rdi
	movl $0x5800, %esi
	xor %rdx, %rdx
	movabs $0x2000, %r10
	lea 0x970(%rbx), %r8
	lea 0x978(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*359(%rbx)

	// vmar_allocate(bad options: plain READ)
	mov 8*62(%rbx), %rdi
	movl $0x1, %esi
	xor %rdx, %rdx
	movabs $0x2000, %r10
	lea 0x970(%rbx), %r8
	lea 0x978(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*360(%rbx)

	// vmar_allocate(ok)
	mov 8*62(%rbx), %rdi
	movl $0x5800, %esi
	xor %rdx, %rdx
	movabs $0x4000, %r10
	lea 0x970(%rbx), %r8
	lea 0x978(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*361(%rbx)
	movq $0, 8*362(%rbx)
	mov 0x970(%rbx), %rax
	test %rax, %rax
	jz vmar_allocate_handle_done
	movq $1, 8*362(%rbx)
vmar_allocate_handle_done:
	movq $0, 8*363(%rbx)
	mov 0x978(%rbx), %rax
	test %rax, %rax
	jz vmar_allocate_addr_done
	movq $1, 8*363(%rbx)
vmar_allocate_addr_done:

	// vmar_map(child_vmar @ offset 0)
	mov 0x970(%rbx), %rdi
	movl $0x403, %esi
	xor %rdx, %rdx
	mov 0x6d0(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x980(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*364(%rbx)
	movq $0, 8*365(%rbx)
	mov 0x980(%rbx), %rax
	cmp 0x978(%rbx), %rax
	jne vmar_allocate_map_match_done
	movq $1, 8*365(%rbx)
vmar_allocate_map_match_done:

	// vmar_allocate(ok without CAN_MAP_SPECIFIC)
	mov 8*62(%rbx), %rdi
	movl $0x1800, %esi
	xor %rdx, %rdx
	movabs $0x3000, %r10
	lea 0x988(%rbx), %r8
	lea 0x990(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*366(%rbx)

	// vmar_map(child without CAN_MAP_SPECIFIC) -> ACCESS_DENIED
	mov 0x988(%rbx), %rdi
	movl $0x403, %esi
	xor %rdx, %rdx
	mov 0x6d0(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x9a0(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*367(%rbx)

	// vmar_map(child without CAN_MAP_SPECIFIC, non-specific) -> somewhere inside child
	mov 0x988(%rbx), %rdi
	movl $0x3, %esi
	xor %rdx, %rdx
	mov 0x6d0(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x9a8(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*368(%rbx)
	movq $0, 8*369(%rbx)
	mov 0x9a8(%rbx), %rax
	mov 0x990(%rbx), %rdx
	cmp %rdx, %rax
	jb vmar_allocate_nonspecific_match_done
	add $0x3000, %rdx
	cmp %rdx, %rax
	jae vmar_allocate_nonspecific_match_done
	movq $1, 8*369(%rbx)
vmar_allocate_nonspecific_match_done:

	// vmar_allocate(grandchild @ exact child offset 0x1000)
	mov 0x970(%rbx), %rdi
	movl $0x4c00, %esi
	movabs $0x1000, %rdx
	movabs $0x1000, %r10
	lea 0x9b8(%rbx), %r8
	lea 0x9c0(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*372(%rbx)
	movq $0, 8*373(%rbx)
	mov 0x9c0(%rbx), %rax
	mov 0x978(%rbx), %rdx
	add $0x1000, %rdx
	cmp %rdx, %rax
	jne vmar_allocate_grandchild_match_done
	movq $1, 8*373(%rbx)
vmar_allocate_grandchild_match_done:

	// vmar_map(grandchild @ offset 0)
	mov 0x9b8(%rbx), %rdi
	movl $0x401, %esi
	xor %rdx, %rdx
	mov 0x6d0(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x9c8(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*374(%rbx)
	movq $0, 8*375(%rbx)
	mov 0x9c8(%rbx), %rax
	cmp 0x9c0(%rbx), %rax
	jne vmar_allocate_grandchild_map_match_done
	movq $1, 8*375(%rbx)
vmar_allocate_grandchild_map_match_done:

	// vmar_allocate(compact grandchild @ exact child offset 0x2000)
	mov 0x970(%rbx), %rdi
	movl $0x4c08, %esi
	movabs $0x2000, %rdx
	movabs $0x1000, %r10
	lea 0x9e8(%rbx), %r8
	lea 0x9f0(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*378(%rbx)

	// vmar_allocate(non-specific child inside compact grandchild) -> compact grandchild base
	mov 0x9e8(%rbx), %rdi
	movl $0x800, %esi
	xor %rdx, %rdx
	movabs $0x1000, %r10
	lea 0xa18(%rbx), %r8
	lea 0xa20(%rbx), %r9
	movabs $28, %rax
	int $0x80
	movq $0, 8*379(%rbx)
	mov 0xa20(%rbx), %rax
	mov 0x9f0(%rbx), %rdx
	cmp %rdx, %rax
	jne vmar_allocate_grandchild_compact_done
	movq $1, 8*379(%rbx)
vmar_allocate_grandchild_compact_done:

	// vmar_allocate(grandchild upper limit inside first child) -> child base + 0x3000
	mov 0x970(%rbx), %rdi
	movl $0xa00, %esi
	movabs $0x4000, %rdx
	movabs $0x1000, %r10
	lea 0x9d0(%rbx), %r8
	lea 0x9d8(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*376(%rbx)
	movq $0, 8*377(%rbx)
	mov 0x9d8(%rbx), %rax
	mov 0x978(%rbx), %rdx
	add $0x3000, %rdx
	cmp %rdx, %rax
	jne vmar_allocate_upper_limit_done
	movq $1, 8*377(%rbx)
vmar_allocate_upper_limit_done:

	// vmar_allocate(root aligned 16KiB)
	mov 8*62(%rbx), %rdi
	movabs $0x0e000800, %rsi
	xor %rdx, %rdx
	movabs $0x1000, %r10
	lea 0x9f8(%rbx), %r8
	lea 0xa00(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*380(%rbx)
	movq $0, 8*381(%rbx)
	mov 0xa00(%rbx), %rax
	test $0x3fff, %rax
	jnz vmar_allocate_align_done
	test %rax, %rax
	jz vmar_allocate_align_done
	movq $1, 8*381(%rbx)
vmar_allocate_align_done:

	// vmar_allocate(root specific misaligned with 16KiB align) -> INVALID_ARGS
	mov 8*62(%rbx), %rdi
	movabs $0x0e000c00, %rsi
	movabs $0x1000, %rdx
	movabs $0x1000, %r10
	lea 0xa08(%rbx), %r8
	lea 0xa10(%rbx), %r9
	movabs $28, %rax
	int $0x80
	mov %rax, 8*382(%rbx)

	// vmar_destroy(first child)
	mov 0x970(%rbx), %rdi
	movabs $29, %rax
	int $0x80
	mov %rax, 8*370(%rbx)

	// root vmar remaps destroyed child range
	mov 8*62(%rbx), %rdi
	movl $0x403, %esi
	mov 0x978(%rbx), %rdx
	movabs $0x0000000100000000, %rax
	sub %rax, %rdx
	mov 0x6d0(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x9e0(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*371(%rbx)

// vmo_create(far-range mapping)
lea 0x6f0(%rbx), %rdx
movabs $0x1000, %rdi
xorl %esi, %esi
movabs $9, %rax
int $0x80
mov %rax, 8*354(%rbx)

// vmar_map(far-range, crosses old bootstrap window and PML4 boundary)
mov 8*62(%rbx), %rdi
movl $0x403, %esi
movabs $0x0000008000010000, %rdx
mov 0x6f0(%rbx), %r10
xor %r8, %r8
movabs $0x1000, %r9
lea 0x6f8(%rbx), %rax
sub $8, %rsp
mov %rax, (%rsp)
movabs $10, %rax
int $0x80
add $8, %rsp
mov %rax, 8*355(%rbx)
mov 0x6f8(%rbx), %rax
mov %rax, 8*356(%rbx)

// Write/read through the far mapped page.
movabs $0x0000008100010000, %r13
movabs $0x8877665544332211, %rax
mov %rax, (%r13)
mov (%r13), %rcx
movq $0, 8*357(%rbx)
cmp %rax, %rcx
jne vmar_far_write_check_done
movq $1, 8*357(%rbx)
vmar_far_write_check_done:

// vmar_unmap(far-range)
mov 8*62(%rbx), %rdi
movabs $0x0000008100010000, %rsi
movabs $0x1000, %rdx
movabs $11, %rax
int $0x80
mov %rax, 8*358(%rbx)

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

	// channel_create(close/read ordering)
	lea 0xC00(%rbx), %rsi
	lea 0xC08(%rbx), %rdx
	xorl %edi, %edi
	movabs $13, %rax
	int $0x80
	mov %rax, 8*318(%rbx)

	// tx bytes @ 0x920
	movabs $0x0102030405060708, %rax
	mov %rax, 0xC20(%rbx)

	// channel_write(h2 -> h3)
	mov 0xC00(%rbx), %rdi
	xorl %esi, %esi
	lea 0xC20(%rbx), %rdx
	movl $8, %r10d
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $14, %rax
	int $0x80
	mov %rax, 8*319(%rbx)

	// close sender h2 while receiver still has one unread message
	mov 0xC00(%rbx), %rdi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*320(%rbx)

	// wait_one(h3, CHANNEL_READABLE | CHANNEL_PEER_CLOSED)
	lea 0xC30(%rbx), %r10
	movq $0, 0xC30(%rbx)
	mov 0xC08(%rbx), %rdi
	movl $0x5, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*321(%rbx)
	mov 0xC30(%rbx), %rax
	mov %rax, 8*322(%rbx)

	// channel_read(h3) should still return the queued message
	movq $0, 0xC50(%rbx)
	movq $0, 0xC58(%rbx)
	mov 0xC08(%rbx), %rdi
	xorl %esi, %esi
	lea 0xC40(%rbx), %rdx
	xorl %r10d, %r10d
	movl $8, %r8d
	xorl %r9d, %r9d
	lea 0xC50(%rbx), %rax
	lea 0xC58(%rbx), %rcx
	sub $16, %rsp
	mov %rax, 0(%rsp)
	mov %rcx, 8(%rsp)
	movabs $15, %rax
	int $0x80
	add $16, %rsp
	mov %rax, 8*323(%rbx)
	mov 0xC50(%rbx), %rax
	mov %rax, 8*324(%rbx)
	movq $0, 8*325(%rbx)
	mov 0xC20(%rbx), %rax
	mov 0xC40(%rbx), %rcx
	cmp %rax, %rcx
	jne channel_close_read_compare_done
	movq $1, 8*325(%rbx)
channel_close_read_compare_done:

	// After draining the queue, only CHANNEL_PEER_CLOSED should remain.
	lea 0xC60(%rbx), %r10
	movq $0, 0xC60(%rbx)
	mov 0xC08(%rbx), %rdi
	movl $0x4, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*326(%rbx)
	mov 0xC60(%rbx), %rax
	mov %rax, 8*327(%rbx)

	// channel_read(peer closed on drained h3)
	movq $0, 0xC50(%rbx)
	movq $0, 0xC58(%rbx)
	mov 0xC08(%rbx), %rdi
	xorl %esi, %esi
	lea 0xC40(%rbx), %rdx
	xorl %r10d, %r10d
	movl $8, %r8d
	xorl %r9d, %r9d
	lea 0xC50(%rbx), %rax
	lea 0xC58(%rbx), %rcx
	sub $16, %rsp
	mov %rax, 0(%rsp)
	mov %rcx, 8(%rsp)
	movabs $15, %rax
	int $0x80
	add $16, %rsp
	mov %rax, 8*328(%rbx)

	// channel_create(writable recovery)
	lea 0xC70(%rbx), %rsi
	lea 0xC78(%rbx), %rdx
	xorl %edi, %edi
	movabs $13, %rax
	int $0x80
	mov %rax, 8*329(%rbx)

	// tx bytes @ 0x990
	movabs $0x0f1e2d3c4b5a6978, %rax
	mov %rax, 0xC90(%rbx)

	// Fill the peer queue to CHANNEL_CAPACITY.
	movq $64, 0xC88(%rbx)
channel_writable_fill_loop:
	mov 0xC88(%rbx), %rax
	test %rax, %rax
	jz channel_writable_fill_done
	mov 0xC70(%rbx), %rdi
	xorl %esi, %esi
	lea 0xC90(%rbx), %rdx
	movl $8, %r10d
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $14, %rax
	int $0x80
	mov %rax, 8*330(%rbx)
	decq 0xC88(%rbx)
	jmp channel_writable_fill_loop
channel_writable_fill_done:

	// The next write should observe backpressure and fail with SHOULD_WAIT.
	mov 0xC70(%rbx), %rdi
	xorl %esi, %esi
	lea 0xC90(%rbx), %rdx
	movl $8, %r10d
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $14, %rax
	int $0x80
	mov %rax, 8*331(%rbx)

	// wait_one(h4, CHANNEL_WRITABLE) should time out while the peer queue is full.
	lea 0xCA0(%rbx), %r10
	movq $0, 0xCA0(%rbx)
	mov 0xC70(%rbx), %rdi
	movl $0x2, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*332(%rbx)
	mov 0xCA0(%rbx), %rax
	mov %rax, 8*333(%rbx)

	// channel_read(h5) frees one slot in the peer queue.
	movq $0, 0xCC0(%rbx)
	movq $0, 0xCC8(%rbx)
	mov 0xC78(%rbx), %rdi
	xorl %esi, %esi
	lea 0xCB0(%rbx), %rdx
	xorl %r10d, %r10d
	movl $8, %r8d
	xorl %r9d, %r9d
	lea 0xCC0(%rbx), %rax
	lea 0xCC8(%rbx), %rcx
	sub $16, %rsp
	mov %rax, 0(%rsp)
	mov %rcx, 8(%rsp)
	movabs $15, %rax
	int $0x80
	add $16, %rsp
	mov %rax, 8*334(%rbx)

	// wait_one(h4, CHANNEL_WRITABLE) should now succeed.
	lea 0xCD0(%rbx), %r10
	movq $0, 0xCD0(%rbx)
	mov 0xC70(%rbx), %rdi
	movl $0x2, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*335(%rbx)
	mov 0xCD0(%rbx), %rax
	mov %rax, 8*336(%rbx)

	// Closing the peer should leave only CHANNEL_PEER_CLOSED visible.
	mov 0xC78(%rbx), %rdi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*337(%rbx)

	lea 0xCE0(%rbx), %r10
	movq $0, 0xCE0(%rbx)
	mov 0xC70(%rbx), %rdi
	movl $0x6, %esi
	xorl %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*338(%rbx)
	mov 0xCE0(%rbx), %rax
	mov %rax, 8*339(%rbx)

	// Further writes should fail with ZX_ERR_PEER_CLOSED, not SHOULD_WAIT.
	mov 0xC70(%rbx), %rdi
	xorl %esi, %esi
	lea 0xC90(%rbx), %rdx
	movl $8, %r10d
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $14, %rax
	int $0x80
	mov %rax, 8*340(%rbx)

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

	// vmo_create(tx page for loan path)
	movabs $0x1000, %rdi
	xorl %esi, %esi
	lea 0x7a0(%rbx), %rdx
	movabs $9, %rax
	int $0x80
	mov %rax, 8*109(%rbx)

	// vmar_map(tx page @ USER_CODE_VA + 0x11000)
	mov 8*62(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x11000, %rdx
	mov 0x7a0(%rbx), %r10
	xor %r8d, %r8d
	movabs $0x1000, %r9
	lea 0x7a8(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*110(%rbx)

	// vmo_create(rx page for loan readback)
	movabs $0x1000, %rdi
	xorl %esi, %esi
	lea 0x7b0(%rbx), %rdx
	movabs $9, %rax
	int $0x80
	mov %rax, 8*111(%rbx)

	// vmar_map(rx page @ USER_CODE_VA + 0x12000)
	mov 8*62(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x12000, %rdx
	mov 0x7b0(%rbx), %r10
	xor %r8d, %r8d
	movabs $0x1000, %r9
	lea 0x7b8(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*112(%rbx)

	// channel_create(for loan path)
	lea 0x7c0(%rbx), %rsi
	lea 0x7c8(%rbx), %rdx
	xorl %edi, %edi
	movabs $13, %rax
	int $0x80
	mov %rax, 8*113(%rbx)

	// seed tx page with a known snapshot pattern
	movabs $0x0000000100011000, %rcx
	movabs $0x1122334455667788, %rax
	mov %rax, 0x0(%rcx)
	movabs $0x8877665544332211, %rax
	mov %rax, 0x8(%rcx)

	// channel_write(full page from tx page)
	mov 0x7c0(%rbx), %rdi
	xorl %esi, %esi
	movabs $0x0000000100011000, %rdx
	movl $4096, %r10d
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $14, %rax
	int $0x80
	mov %rax, 8*114(%rbx)

	// mutate sender page after write; receiver must still observe the old snapshot
	movabs $0x0000000100011000, %rcx
	movabs $0x8899aabbccddeeff, %rax
	mov %rax, 0x0(%rcx)

	// channel_read(full page into rx page)
	movq $0, 0x7d0(%rbx)
	movq $0, 0x7d8(%rbx)
	mov 0x7c8(%rbx), %rdi
	xorl %esi, %esi
	movabs $0x0000000100012000, %rdx
	xorl %r10d, %r10d
	movl $4096, %r8d
	xorl %r9d, %r9d
	lea 0x7d0(%rbx), %rax
	lea 0x7d8(%rbx), %rcx
	sub $16, %rsp
	mov %rax, 0(%rsp)
	mov %rcx, 8(%rsp)
	movabs $15, %rax
	int $0x80
	add $16, %rsp
	mov %rax, 8*115(%rbx)
	mov 0x7d0(%rbx), %rax
	mov %rax, 8*116(%rbx)

	// snapshot check: sender sees mutated bytes, receiver sees original bytes
	movq $0, 8*117(%rbx)
	movabs $0x0000000100011000, %rsi
	movabs $0x0000000100012000, %rdi
	mov (%rsi), %r8
	mov (%rdi), %r9
	movabs $0x8899aabbccddeeff, %rax
	cmp %rax, %r8
	jne channel_loan_snapshot_done
	movabs $0x1122334455667788, %rax
	cmp %rax, %r9
	jne channel_loan_snapshot_done
	movq $1, 8*117(%rbx)
channel_loan_snapshot_done:

	// remap-fill COW check: receiver write should split privately without corrupting sender
	mov 8*316(%rbx), %rax
	mov %rax, 0x7e0(%rbx)
	movabs $0x5566778899aabbcc, %rax
	movabs $0x0000000100012000, %rcx
	mov %rax, 0x0(%rcx)
	movq $0, 8*317(%rbx)
	mov 0x7e0(%rbx), %r8
	mov 8*316(%rbx), %r9
	lea 1(%r8), %r10
	cmp %r10, %r9
	jne channel_loan_remap_cow_done
	movabs $0x0000000100011000, %rsi
	movabs $0x0000000100012000, %rdi
	mov (%rsi), %r8
	mov (%rdi), %r9
	movabs $0x8899aabbccddeeff, %rax
	cmp %rax, %r8
	jne channel_loan_remap_cow_done
	movabs $0x5566778899aabbcc, %rax
	cmp %rax, %r9
	jne channel_loan_remap_cow_done
	movq $1, 8*317(%rbx)
channel_loan_remap_cow_done:

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

// timer_set(deadline=t0+2s)
mov 0x698(%rbx), %rdi
mov %r12, %rsi
add $2000000000, %rsi
xor %rdx, %rdx
movabs $7, %rax
int $0x80
mov %rax, 8*29(%rbx)

// object_wait_one(timer, TIMER_SIGNALED, deadline=t0+750ms, observed=&obs2) should time out
lea 0x6b0(%rbx), %rcx
movq $0, (%rcx)
mov 0x698(%rbx), %rdi
movl $0x8, %esi
mov %r12, %rdx
add $750000000, %rdx
mov %rcx, %r10
movabs $1, %rax
int $0x80
mov %rax, 8*37(%rbx)
mov (%rcx), %rax
mov %rax, 8*38(%rbx)

// object_wait_one(timer, TIMER_SIGNALED, deadline=t0+2s, observed=&obs3) should be OK
lea 0x6b8(%rbx), %rcx
movq $0, (%rcx)
mov 0x698(%rbx), %rdi
movl $0x8, %esi
mov %r12, %rdx
add $2000000000, %rdx
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

	// eventpair_create(fresh pair for handle duplicate/replace + object_signal)
	lea 0x820(%rbx), %rsi
	lea 0x828(%rbx), %rdx
	xorl %edi, %edi
	movabs $16, %rax
	int $0x80

	// handle_duplicate(h0, SAME_RIGHTS)
	mov 0x820(%rbx), %rdi
	movl $0xffffffff, %esi
	lea 0x830(%rbx), %rdx
	movabs $18, %rax
	int $0x80
	mov %rax, 8*118(%rbx)

	// duplicated handle must be distinct and non-zero
	movq $0, 8*119(%rbx)
	mov 0x820(%rbx), %rsi
	mov 0x830(%rbx), %rdi
	test %rdi, %rdi
	jz handle_duplicate_distinct_done
	cmp %rsi, %rdi
	je handle_duplicate_distinct_done
	movq $1, 8*119(%rbx)
handle_duplicate_distinct_done:

	// object_signal(dup_h0, USER_SIGNAL_2)
	mov 0x830(%rbx), %rdi
	xorl %esi, %esi
	movl $0x04000000, %edx
	movabs $20, %rax
	int $0x80
	mov %rax, 8*120(%rbx)

	// wait_one(orig_h0, USER_SIGNAL_2)
	movq $0, 0x838(%rbx)
	mov 0x820(%rbx), %rdi
	movl $0x04000000, %esi
	xorl %edx, %edx
	lea 0x838(%rbx), %r10
	movabs $1, %rax
	int $0x80
	mov %rax, 8*121(%rbx)
	mov 0x838(%rbx), %rax
	mov %rax, 8*122(%rbx)

	// handle_duplicate(h0, WAIT only)
	mov 0x820(%rbx), %rdi
	movl $0x4000, %esi
	lea 0x840(%rbx), %rdx
	movabs $18, %rax
	int $0x80
	mov %rax, 8*123(%rbx)

	// object_signal(wait_only_dup, USER_SIGNAL_3) => ACCESS_DENIED
	mov 0x840(%rbx), %rdi
	xorl %esi, %esi
	movl $0x08000000, %edx
	movabs $20, %rax
	int $0x80
	mov %rax, 8*124(%rbx)

	// handle_replace(h1, SAME_RIGHTS)
	mov 0x828(%rbx), %rdi
	movl $0xffffffff, %esi
	lea 0x848(%rbx), %rdx
	movabs $19, %rax
	int $0x80
	mov %rax, 8*125(%rbx)

	// old h1 must be dead after replace
	movq $0, 0x850(%rbx)
	mov 0x828(%rbx), %rdi
	movl $0x10000000, %esi
	xorl %edx, %edx
	lea 0x850(%rbx), %r10
	movabs $1, %rax
	int $0x80
	mov %rax, 8*126(%rbx)

	// object_signal(new_h1, USER_SIGNAL_4)
	mov 0x848(%rbx), %rdi
	xorl %esi, %esi
	movl $0x10000000, %edx
	movabs $20, %rax
	int $0x80
	mov %rax, 8*127(%rbx)

	// wait_one(new_h1, USER_SIGNAL_4)
	movq $0, 0x850(%rbx)
	mov 0x848(%rbx), %rdi
	movl $0x10000000, %esi
	xorl %edx, %edx
	lea 0x850(%rbx), %r10
	movabs $1, %rax
	int $0x80
	mov %rax, 8*128(%rbx)
	mov 0x850(%rbx), %rax
	mov %rax, 8*129(%rbx)

	// object_signal(bad mask: PEER_CLOSED)
	mov 0x848(%rbx), %rdi
	movl $0x4, %esi
	xorl %edx, %edx
	movabs $20, %rax
	int $0x80
	mov %rax, 8*130(%rbx)

	// object_wait_async(new_h1, port_h, key=0x6001, USER_SIGNAL_5)
	mov 0x848(%rbx), %rdi
	mov 0x688(%rbx), %rsi
	movabs $0x6001, %rdx
	movl $0x20000000, %r10d
	xorl %r8d, %r8d
	movabs $2, %rax
	int $0x80
	mov %rax, 8*131(%rbx)

	// object_signal(new_h1, USER_SIGNAL_5)
	mov 0x848(%rbx), %rdi
	xorl %esi, %esi
	movl $0x20000000, %edx
	movabs $20, %rax
	int $0x80
	mov %rax, 8*132(%rbx)

	// port_wait(signal packet from object_signal)
	mov 0x688(%rbx), %rdi
	xor %rsi, %rsi
	lea 0x860(%rbx), %rdx
	movabs $5, %rax
	int $0x80
	mov %rax, 8*133(%rbx)
	mov 0x860(%rbx), %rax
	mov %rax, 8*134(%rbx)

	// bootstrap futex source/target words live in the mapped VMAR page.
	movabs $0x0000000100010000, %r14
	mov %r14, %r15
	add $4, %r15
	movl $0x1234, (%r14)
	movl $0, (%r15)

	// futex_wait(source, mismatched value) => BAD_STATE
	mov %r14, %rdi
	movl $0x5678, %esi
	xorl %edx, %edx
	xorl %r10d, %r10d
	movabs $21, %rax
	int $0x80
	mov %rax, 8*136(%rbx)

	// futex_wait(source, self-thread owner) => INVALID_ARGS
	mov %r14, %rdi
	movl $0x1234, %esi
	mov 8*135(%rbx), %rdx
	xorl %r10d, %r10d
	movabs $21, %rax
	int $0x80
	mov %rax, 8*137(%rbx)

	// futex_get_owner(source) => ZX_OK, owner=0
	mov %r14, %rdi
	lea 0x868(%rbx), %rsi
	movabs $24, %rax
	int $0x80
	mov %rax, 8*139(%rbx)
	mov 0x868(%rbx), %rax
	mov %rax, 8*140(%rbx)

	// futex_wait(source, invalid owner, deadline=0) => TIMED_OUT
	mov %r14, %rdi
	movl $0x1234, %esi
	xorl %edx, %edx
	xorl %r10d, %r10d
	movabs $21, %rax
	int $0x80
	mov %rax, 8*138(%rbx)

	// futex_get_owner(source) after timeout => ZX_OK, owner=0
	mov %r14, %rdi
	lea 0x870(%rbx), %rsi
	movabs $24, %rax
	int $0x80
	mov %rax, 8*141(%rbx)
	mov 0x870(%rbx), %rax
	mov %rax, 8*142(%rbx)

	// futex_requeue(source -> same source) => INVALID_ARGS
	mov %r14, %rdi
	xorl %esi, %esi
	movl $0x1234, %edx
	mov %r14, %r10
	xorl %r8d, %r8d
	xorl %r9d, %r9d
	movabs $23, %rax
	int $0x80
	mov %rax, 8*143(%rbx)

	// futex_requeue(source -> target, wrong-type owner=root_vmar) => WRONG_TYPE
	mov %r14, %rdi
	xorl %esi, %esi
	movl $0x1234, %edx
	mov %r15, %r10
	xorl %r8d, %r8d
	mov 8*62(%rbx), %r9
	movabs $23, %rax
	int $0x80
	mov %rax, 8*144(%rbx)

	// futex_requeue(source -> target, owner=self-thread) => ZX_OK
	mov %r14, %rdi
	xorl %esi, %esi
	movl $0x1234, %edx
	mov %r15, %r10
	xorl %r8d, %r8d
	mov 8*135(%rbx), %r9
	movabs $23, %rax
	int $0x80
	mov %rax, 8*145(%rbx)

	// futex_get_owner(target) => ZX_OK, owner matches bootstrap self koid
	mov %r15, %rdi
	lea 0x878(%rbx), %rsi
	movabs $24, %rax
	int $0x80
	mov %rax, 8*146(%rbx)
	movq $0, 8*147(%rbx)
	mov 0x878(%rbx), %rax
	cmp 8*151(%rbx), %rax
	jne futex_owner_match_done
	movq $1, 8*147(%rbx)
futex_owner_match_done:

	// futex_wake(target, 0) => ZX_OK and owner cleared
	mov %r15, %rdi
	xorl %esi, %esi
	movabs $22, %rax
	int $0x80
	mov %rax, 8*148(%rbx)

	// futex_get_owner(target) after wake => ZX_OK, owner=0
	mov %r15, %rdi
	lea 0x880(%rbx), %rsi
	movabs $24, %rax
	int $0x80
	mov %rax, 8*149(%rbx)
	mov 0x880(%rbx), %rax
	mov %rax, 8*150(%rbx)

	// vmo_create(thread stack page)
	lea 0x888(%rbx), %rdx
	movabs $0x1000, %rdi
	xorl %esi, %esi
	movabs $9, %rax
	int $0x80

	// vmar_map(thread stack @ USER_CODE_VA + 0x13000)
	mov 8*62(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x13000, %rdx
	mov 0x888(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x890(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp

	// thread_create(self_process, NULL, 0, 0, &thread_h)
	mov 8*300(%rbx), %rdi
	xor %rsi, %rsi
	xor %rdx, %rdx
	xor %r10d, %r10d
	lea 0x898(%rbx), %r8
	movabs $25, %rax
	int $0x80
	mov %rax, 8*301(%rbx)

	// thread_start(thread_h, thread_worker_entry, stack_top, source_futex, 0)
	mov 0x898(%rbx), %rdi
	lea thread_worker_entry(%rip), %rsi
	mov 0x890(%rbx), %rdx
	add $0x1000, %rdx
	mov %r14, %r10
	xor %r8, %r8
	movabs $26, %rax
	int $0x80
	mov %rax, 8*302(%rbx)

	// futex_wait(source, 0, INVALID, forever) -> child should wake us
	movl $0, (%r14)
	mov %r14, 8*308(%rbx)
	movq $1, 8*307(%rbx)
	mov %r14, %rdi
	xorl %esi, %esi
	xorl %edx, %edx
	movabs $0x7fffffffffffffff, %r10
	movabs $21, %rax
	int $0x80
	mov %rax, 8*304(%rbx)

	// resume check: child ran and futex word now equals 1
	movq $0, 8*306(%rbx)
	cmpq $1, 8*303(%rbx)
	jne thread_resume_done
	mov (%r14), %eax
	cmpl $1, %eax
	jne thread_resume_done
	movq $1, 8*306(%rbx)
thread_resume_done:

	// eventpair_create(fresh pair for threaded wait_one wake)
	lea 0x8a0(%rbx), %rsi
	lea 0x8a8(%rbx), %rdx
	xorl %edi, %edi
	movabs $16, %rax
	int $0x80

	// command worker: signal peer on eventpair h1
	mov 0x8a8(%rbx), %rax
	mov %rax, 8*308(%rbx)
	movq $2, 8*307(%rbx)
	movq $0, 0x8b0(%rbx)
	mov 0x8a0(%rbx), %rdi
	movl $0x40000000, %esi
	movabs $0x7fffffffffffffff, %rdx
	lea 0x8b0(%rbx), %r10
	movabs $1, %rax
	int $0x80
	mov %rax, 8*309(%rbx)
	mov 0x8b0(%rbx), %rax
	mov %rax, 8*310(%rbx)

	// command worker: queue a user packet into bootstrap port, then block on port_wait
	mov 8*35(%rbx), %rax
	mov %rax, 8*308(%rbx)
	movq $3, 8*307(%rbx)
	lea 0x8c0(%rbx), %rdx
	mov 8*35(%rbx), %rdi
	movabs $0x7fffffffffffffff, %rsi
	movabs $5, %rax
	int $0x80
	mov %rax, 8*312(%rbx)
	mov 0x8c0(%rbx), %rax
	mov %rax, 8*313(%rbx)
	mov 0x8c8(%rbx), %eax
	mov %rax, 8*314(%rbx)

	// process_create(self_process, NULL, 0, 0, &child_process, &child_root_vmar)
	mov 8*300(%rbx), %rdi
	xor %rsi, %rsi
	xor %rdx, %rdx
	xor %r10d, %r10d
	lea 0x900(%rbx), %r8
	lea 0x908(%rbx), %r9
	movabs $27, %rax
	int $0x80
	mov %rax, 8*344(%rbx)

	// vmo_create(child code image, 0x8000)
	lea 0x910(%rbx), %rdx
	movabs $0x8000, %rdi
	xorl %esi, %esi
	movabs $9, %rax
	int $0x80

	// parent root_vmar maps code VMO at USER_CODE_VA + 0x20000
	mov 8*62(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x20000, %rdx
	mov 0x910(%rbx), %r10
	xor %r8, %r8
	movabs $0x8000, %r9
	lea 0x918(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*345(%rbx)

	// copy current runner code bytes into the shared code VMO
	movabs $0x0000000100000000, %rsi
	mov 0x918(%rbx), %rdi
	movabs $0x8000, %rcx
	rep movsb

	// vmo_create(child shared page, 0x1000)
	lea 0x920(%rbx), %rdx
	movabs $0x1000, %rdi
	xorl %esi, %esi
	movabs $9, %rax
	int $0x80

	// parent root_vmar maps shared page at USER_CODE_VA + 0x28000
	mov 8*62(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x28000, %rdx
	mov 0x920(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x928(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*346(%rbx)

	// materialize and initialize the shared page before importing it into the child
	mov 0x928(%rbx), %rcx
	movq $0, 0x0(%rcx)
	movl $0, 0x8(%rcx)

	// vmo_create(child stack page, 0x1000)
	lea 0x930(%rbx), %rdx
	movabs $0x1000, %rdi
	xorl %esi, %esi
	movabs $9, %rax
	int $0x80

	// child root_vmar maps code at USER_CODE_VA
	mov 0x908(%rbx), %rdi
	movl $0x403, %esi
	xor %rdx, %rdx
	mov 0x910(%rbx), %r10
	xor %r8, %r8
	movabs $0x8000, %r9
	lea 0x940(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*347(%rbx)

	// child root_vmar maps shared page at USER_SHARED_VA
	mov 0x908(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x8000, %rdx
	mov 0x920(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x948(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*348(%rbx)

	// child root_vmar maps stack at USER_STACK_VA
	mov 0x908(%rbx), %rdi
	movl $0x403, %esi
	movabs $0x9000, %rdx
	mov 0x930(%rbx), %r10
	xor %r8, %r8
	movabs $0x1000, %r9
	lea 0x950(%rbx), %rax
	sub $8, %rsp
	mov %rax, (%rsp)
	movabs $10, %rax
	int $0x80
	add $8, %rsp
	mov %rax, 8*349(%rbx)

	// thread_create(child_process, NULL, 0, 0, &child_thread_h)
	mov 0x900(%rbx), %rdi
	xor %rsi, %rsi
	xor %rdx, %rdx
	xor %r10d, %r10d
	lea 0x938(%rbx), %r8
	movabs $25, %rax
	int $0x80
	mov %rax, 8*350(%rbx)

	// thread_start(child_thread, process_child_entry, USER_STACK_TOP, USER_SHARED_VA, 0)
	mov 0x938(%rbx), %rdi
	lea process_child_entry(%rip), %rsi
	movabs $0x0000000100009000, %rdx
	add $0x1000, %rdx
	movabs $0x0000000100008000, %r10
	xor %r8, %r8
	movabs $26, %rax
	int $0x80
	mov %rax, 8*351(%rbx)

	// park the original bootstrap worker thread so the child process thread can run next
	mov 0x928(%rbx), %rcx
	lea 0xc(%rcx), %rax
	mov %rax, 8*308(%rbx)
	movq $4, 8*307(%rbx)

	// wait on the shared futex word the child will wake
	mov 0x928(%rbx), %rcx
	lea 0x8(%rcx), %rdi
	xorl %esi, %esi
	xorl %edx, %edx
	movabs $0x7fffffffffffffff, %r10
	movabs $21, %rax
	int $0x80
	mov %rax, 8*353(%rbx)
	mov 0x928(%rbx), %rcx
	mov (%rcx), %rax
	mov %rax, 8*352(%rbx)

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

thread_worker_entry:
	movabs $0x0000000100008000, %rbx
	movq $1, 8*303(%rbx)
thread_worker_spin:
	mov 8*307(%rbx), %rax
	test %rax, %rax
	jz thread_worker_spin_pause
	cmp $1, %rax
	je thread_worker_futex
	cmp $2, %rax
	je thread_worker_signal_peer
	cmp $3, %rax
	je thread_worker_queue_port
	cmp $4, %rax
	je thread_worker_park
	movq $0, 8*307(%rbx)
thread_worker_spin_pause:
	pause
	jmp thread_worker_spin

thread_worker_futex:
	movq $0, 8*307(%rbx)
	mov 8*308(%rbx), %rdi
	movl $1, (%rdi)
	movl $1, %esi
	movabs $22, %rax
	int $0x80
	mov %rax, 8*305(%rbx)
	jmp thread_worker_spin

thread_worker_signal_peer:
	movq $0, 8*307(%rbx)
	mov 8*308(%rbx), %rdi
	xorl %esi, %esi
	movl $0x40000000, %edx
	movabs $17, %rax
	int $0x80
	mov %rax, 8*311(%rbx)
	jmp thread_worker_spin

thread_worker_queue_port:
	movq $0, 8*307(%rbx)
	mov 8*308(%rbx), %rdi
	lea 0x8e0(%rbx), %rsi
	movabs $0x7001, %rax
	mov %rax, 0x00(%rsi)
	movl $0, 0x08(%rsi)
	movl $0, 0x0c(%rsi)
	movabs $0x55, %rax
	mov %rax, 0x10(%rsi)
	movq $0, 0x18(%rsi)
	movq $0, 0x20(%rsi)
	movq $0, 0x28(%rsi)
	movabs $4, %rax
	int $0x80
	mov %rax, 8*315(%rbx)
	jmp thread_worker_spin

thread_worker_park:
	movq $0, 8*307(%rbx)
	mov 8*308(%rbx), %rdi
	xorl %esi, %esi
	xorl %edx, %edx
	movabs $0x7fffffffffffffff, %r10
	movabs $21, %rax
	int $0x80
	jmp thread_worker_spin

process_child_entry:
	mov %rdi, %rbx
	movq $1, 0x0(%rbx)
	movl $1, 0x8(%rbx)
	lea 0x8(%rbx), %rdi
	movl $1, %esi
	movabs $22, %rax
	int $0x80
process_child_spin:
	pause
	jmp process_child_spin

axle_user_prog_end:
