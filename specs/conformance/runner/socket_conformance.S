.section .text.axle_userprog, "ax"
.global axle_user_prog_start
.global axle_user_prog_end

axle_user_prog_start:
	movabs $0x0000000100008000, %rbx

	// socket_create(STREAM, &sock0, &sock1)
	lea 0x1000(%rbx), %rsi
	lea 0x1008(%rbx), %rdx
	xorl %edi, %edi
	movabs $36, %rax
	int $0x80
	mov %rax, 8*456(%rbx)
	test %rax, %rax
	jne user_fail

	// wait_one(sock0, OBJECT_WRITABLE, deadline=0)
	lea 8*458(%rbx), %r10
	movq $0, (%r10)
	mov 0x1000(%rbx), %rdi
	movl $0x2, %esi
	xor %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*457(%rbx)
	mov (%r10), %rax
	mov %rax, 8*458(%rbx)
	cmp $0, 8*457(%rbx)
	jne user_fail

	// tx bytes @ 0x1800 (16 bytes)
	movabs $0x1122334455667788, %rax
	mov %rax, 0x1100(%rbx)
	movabs $0x99aabbccddeeff00, %rax
	mov %rax, 0x1108(%rbx)

	// socket_write(sock0, 0, tx, 16, &actual)
	mov 0x1000(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1100(%rbx), %rdx
	movabs $16, %r10
	lea 0x1010(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*459(%rbx)
	cmp $0, 8*459(%rbx)
	jne user_fail

	// wait_one(sock1, OBJECT_READABLE, deadline=0)
	lea 8*461(%rbx), %r10
	movq $0, (%r10)
	mov 0x1008(%rbx), %rdi
	movl $0x1, %esi
	xor %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*460(%rbx)
	mov (%r10), %rax
	mov %rax, 8*461(%rbx)
	cmp $0, 8*460(%rbx)
	jne user_fail

	// socket_read(sock1, PEEK, rx, 16, &actual)
	mov 0x1008(%rbx), %rdi
	movl $1, %esi
	lea 0x1120(%rbx), %rdx
	movabs $16, %r10
	lea 0x1018(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*462(%rbx)
	cmp $0, 8*462(%rbx)
	jne user_fail

	lea 0x1100(%rbx), %rsi
	lea 0x1120(%rbx), %rdi
	mov $2, %rcx
socket_peek_cmp:
	mov (%rsi), %r8
	mov (%rdi), %r9
	cmp %r8, %r9
	jne user_fail
	add $8, %rsi
	add $8, %rdi
	loop socket_peek_cmp
	movq $1, 8*463(%rbx)

	// socket_read(sock1, 0, rx2, 16, &actual)
	mov 0x1008(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1140(%rbx), %rdx
	movabs $16, %r10
	lea 0x1020(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*464(%rbx)
	cmp $0, 8*464(%rbx)
	jne user_fail

	lea 0x1100(%rbx), %rsi
	lea 0x1140(%rbx), %rdi
	mov $2, %rcx
socket_read_cmp:
	mov (%rsi), %r8
	mov (%rdi), %r9
	cmp %r8, %r9
	jne user_fail
	add $8, %rsi
	add $8, %rdi
	loop socket_read_cmp
	movq $1, 8*465(%rbx)

	// close peer socket handle
	mov 0x1000(%rbx), %rdi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*466(%rbx)
	cmp $0, 8*466(%rbx)
	jne user_fail

	// wait_one(sock1, OBJECT_PEER_CLOSED, deadline=0)
	lea 8*468(%rbx), %r10
	movq $0, (%r10)
	mov 0x1008(%rbx), %rdi
	movl $0x4, %esi
	xor %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*467(%rbx)
	mov (%r10), %rax
	mov %rax, 8*468(%rbx)
	cmp $0, 8*467(%rbx)
	jne user_fail

	// socket_write(sock1, 0, tx, 1, &actual) => PEER_CLOSED
	mov 0x1008(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1100(%rbx), %rdx
	movabs $1, %r10
	lea 0x1028(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*469(%rbx)

	// socket_read(sock1, 0, rx3, 16, &actual) => PEER_CLOSED
	mov 0x1008(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1160(%rbx), %rdx
	movabs $16, %r10
	lea 0x1030(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*470(%rbx)

	// socket_create(STREAM, &fill0, &fill1)
	lea 0x1040(%rbx), %rsi
	lea 0x1048(%rbx), %rdx
	xorl %edi, %edi
	movabs $36, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	// fill tx buffer @ 0x1800 with 3000 bytes of 0x5a
	cld
	lea 0x1200(%rbx), %rdi
	mov $3000, %rcx
	movb $0x5a, %al
	rep stosb

	// first write 3000 bytes
	mov 0x1040(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1200(%rbx), %rdx
	movabs $3000, %r10
	lea 0x1050(%rbx), %r8
	movabs $37, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	// second write 3000 bytes => short write
	mov 0x1040(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1200(%rbx), %rdx
	movabs $3000, %r10
	lea 0x1058(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*471(%rbx)
	mov 0x1058(%rbx), %rax
	mov %rax, 8*472(%rbx)

	// third write 1 byte => SHOULD_WAIT
	mov 0x1040(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1200(%rbx), %rdx
	movabs $1, %r10
	lea 0x1060(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*473(%rbx)

	// drain 4096 bytes from peer
	mov 0x1048(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1160(%rbx), %rdx
	movabs $1, %r10
	lea 0x1068(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*474(%rbx)

	// write 1 byte again => writable recovered
	mov 0x1040(%rbx), %rdi
	xorl %esi, %esi
	lea 0x1200(%rbx), %rdx
	movabs $1, %r10
	lea 0x1070(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*475(%rbx)

	// socket_create(STREAM, &dup0, &dup1)
	lea 0x1080(%rbx), %rsi
	lea 0x1088(%rbx), %rdx
	xorl %edi, %edi
	movabs $36, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	// duplicate dup0
	mov 0x1080(%rbx), %rdi
	movl $0xffffffff, %esi
	lea 0x1090(%rbx), %rdx
	movabs $18, %rax
	int $0x80
	mov %rax, 8*476(%rbx)

	// close original dup0
	mov 0x1080(%rbx), %rdi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*477(%rbx)

	// wait_one(dup1, OBJECT_PEER_CLOSED, deadline=0) => TIMED_OUT
	lea 0x1098(%rbx), %r10
	movq $0, (%r10)
	mov 0x1088(%rbx), %rdi
	movl $0x4, %esi
	xor %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*478(%rbx)

	// close duplicate
	mov 0x1090(%rbx), %rdi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*479(%rbx)

	// wait_one(dup1, OBJECT_PEER_CLOSED, deadline=0) => OK
	lea 8*481(%rbx), %r10
	movq $0, (%r10)
	mov 0x1088(%rbx), %rdi
	movl $0x4, %esi
	xor %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*480(%rbx)
	mov (%r10), %rax
	mov %rax, 8*481(%rbx)
	cmp $0, 8*480(%rbx)
	jne user_fail

	movq $1, 0x00(%rbx)
	int3

user_fail:
	movq $1, 0x00(%rbx)
	int3

axle_user_prog_end:
