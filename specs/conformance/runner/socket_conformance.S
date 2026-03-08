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
	mov 0x1000(%rbx), %edi
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
	mov 0x1000(%rbx), %edi
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
	mov 0x1008(%rbx), %edi
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
	mov 0x1008(%rbx), %edi
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
	mov 0x1008(%rbx), %edi
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
	mov 0x1000(%rbx), %edi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*466(%rbx)
	cmp $0, 8*466(%rbx)
	jne user_fail

	// wait_one(sock1, OBJECT_PEER_CLOSED, deadline=0)
	lea 8*468(%rbx), %r10
	movq $0, (%r10)
	mov 0x1008(%rbx), %edi
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
	mov 0x1008(%rbx), %edi
	xorl %esi, %esi
	lea 0x1100(%rbx), %rdx
	movabs $1, %r10
	lea 0x1028(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*469(%rbx)

	// socket_read(sock1, 0, rx3, 16, &actual) => PEER_CLOSED
	mov 0x1008(%rbx), %edi
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
	mov 0x1040(%rbx), %edi
	xorl %esi, %esi
	lea 0x1200(%rbx), %rdx
	movabs $3000, %r10
	lea 0x1050(%rbx), %r8
	movabs $37, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	// second write 3000 bytes => short write
	mov 0x1040(%rbx), %edi
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
	mov 0x1040(%rbx), %edi
	xorl %esi, %esi
	lea 0x1200(%rbx), %rdx
	movabs $1, %r10
	lea 0x1060(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*473(%rbx)

	// drain 4096 bytes from peer
	mov 0x1048(%rbx), %edi
	xorl %esi, %esi
	lea 0x1160(%rbx), %rdx
	movabs $1, %r10
	lea 0x1068(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*474(%rbx)

	// write 1 byte again => writable recovered
	mov 0x1040(%rbx), %edi
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
	mov 0x1080(%rbx), %edi
	movl $0xffffffff, %esi
	lea 0x1090(%rbx), %rdx
	movabs $18, %rax
	int $0x80
	mov %rax, 8*476(%rbx)

	// close original dup0
	mov 0x1080(%rbx), %edi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*477(%rbx)

	// wait_one(dup1, OBJECT_PEER_CLOSED, deadline=0) => TIMED_OUT
	lea 0x1098(%rbx), %r10
	movq $0, (%r10)
	mov 0x1088(%rbx), %edi
	movl $0x4, %esi
	xor %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*478(%rbx)

	// close duplicate
	mov 0x1090(%rbx), %edi
	movabs $0, %rax
	int $0x80
	mov %rax, 8*479(%rbx)

	// wait_one(dup1, OBJECT_PEER_CLOSED, deadline=0) => OK
	lea 8*481(%rbx), %r10
	movq $0, (%r10)
	mov 0x1088(%rbx), %edi
	movl $0x4, %esi
	xor %edx, %edx
	movabs $1, %rax
	int $0x80
	mov %rax, 8*480(%rbx)
	mov (%r10), %rax
	mov %rax, 8*481(%rbx)
	cmp $0, 8*480(%rbx)
	jne user_fail

	// socket_create(DATAGRAM, ...) => NOT_SUPPORTED
	lea 0x1490(%rbx), %rsi
	lea 0x1498(%rbx), %rdx
	movl $1, %edi
	movabs $36, %rax
	int $0x80
	mov %rax, 8*482(%rbx)

	// socket_create(invalid options=2, ...) => INVALID_ARGS
	lea 0x1490(%rbx), %rsi
	lea 0x1498(%rbx), %rdx
	movl $2, %edi
	movabs $36, %rax
	int $0x80
	mov %rax, 8*483(%rbx)

	// create stream pair for option/null-pointer edge cases
	lea 0x14a0(%rbx), %rsi
	lea 0x14a8(%rbx), %rdx
	xorl %edi, %edi
	movabs $36, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	// socket_write(sock_args0, 0, NULL, 0, NULL) => OK
	mov 0x14a0(%rbx), %edi
	xorl %esi, %esi
	xor %edx, %edx
	xor %r10d, %r10d
	xor %r8d, %r8d
	movabs $37, %rax
	int $0x80
	mov %rax, 8*484(%rbx)

	// socket_read(sock_args1, 0, NULL, 1, &actual) => INVALID_ARGS
	mov 0x14a8(%rbx), %edi
	xorl %esi, %esi
	xor %edx, %edx
	movabs $1, %r10
	lea 0x14b0(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*485(%rbx)

	// socket_write(sock_args0, invalid options=1, buf, 1, &actual) => INVALID_ARGS
	mov 0x14a0(%rbx), %edi
	movl $1, %esi
	lea 0x1100(%rbx), %rdx
	movabs $1, %r10
	lea 0x14b8(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*486(%rbx)

	// socket_read(sock_args1, invalid options=2, buf, 1, &actual) => INVALID_ARGS
	mov 0x14a8(%rbx), %edi
	movl $2, %esi
	lea 0x1180(%rbx), %rdx
	movabs $1, %r10
	lea 0x14c0(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*487(%rbx)

	// write one byte then read it back with actual == NULL
	mov 0x14a0(%rbx), %edi
	xorl %esi, %esi
	lea 0x1100(%rbx), %rdx
	movabs $1, %r10
	lea 0x14c8(%rbx), %r8
	movabs $37, %rax
	int $0x80
	test %rax, %rax
	jne user_fail
	mov 0x14a8(%rbx), %edi
	xorl %esi, %esi
	lea 0x1180(%rbx), %rdx
	movabs $1, %r10
	xor %r8d, %r8d
	movabs $38, %rax
	int $0x80
	mov %rax, 8*488(%rbx)

	// wait_async socket readable -> port packet
	lea 0x14d0(%rbx), %rsi
	xorl %edi, %edi
	movabs $3, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	lea 0x14d8(%rbx), %rsi
	lea 0x14e0(%rbx), %rdx
	xorl %edi, %edi
	movabs $36, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	mov 0x14e0(%rbx), %edi
	mov 0x14d0(%rbx), %esi
	movabs $0x7001, %rdx
	movl $0x1, %r10d
	xorl %r8d, %r8d
	movabs $2, %rax
	int $0x80
	mov %rax, 8*489(%rbx)

	mov 0x14d8(%rbx), %edi
	xorl %esi, %esi
	lea 0x1100(%rbx), %rdx
	movabs $1, %r10
	lea 0x14e8(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*490(%rbx)

	mov 0x14d0(%rbx), %edi
	xor %esi, %esi
	lea 0x1500(%rbx), %rdx
	movabs $5, %rax
	int $0x80
	mov %rax, 8*491(%rbx)
	mov 0x1500(%rbx), %rax
	mov %rax, 8*492(%rbx)
	mov 0x1508(%rbx), %rax
	mov %rax, 8*493(%rbx)
	mov 0x1510(%rbx), %rax
	shr $32, %rax
	mov %rax, 8*494(%rbx)

	// wait_async socket writable -> immediate port packet
	lea 0x1520(%rbx), %rsi
	xorl %edi, %edi
	movabs $3, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	lea 0x1528(%rbx), %rsi
	lea 0x1530(%rbx), %rdx
	xorl %edi, %edi
	movabs $36, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	mov 0x1528(%rbx), %edi
	mov 0x1520(%rbx), %esi
	movabs $0x7002, %rdx
	movl $0x2, %r10d
	xorl %r8d, %r8d
	movabs $2, %rax
	int $0x80
	mov %rax, 8*495(%rbx)

	mov 0x1520(%rbx), %edi
	xor %esi, %esi
	lea 0x1540(%rbx), %rdx
	movabs $5, %rax
	int $0x80
	mov %rax, 8*496(%rbx)

	// duplicated socket should keep data flow alive after original close
	lea 0x1580(%rbx), %rsi
	lea 0x1588(%rbx), %rdx
	xorl %edi, %edi
	movabs $36, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	mov 0x1580(%rbx), %edi
	movl $0xffffffff, %esi
	lea 0x1590(%rbx), %rdx
	movabs $18, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	mov 0x1580(%rbx), %edi
	movabs $0, %rax
	int $0x80
	test %rax, %rax
	jne user_fail

	mov 0x1590(%rbx), %edi
	xorl %esi, %esi
	lea 0x1100(%rbx), %rdx
	movabs $16, %r10
	lea 0x1598(%rbx), %r8
	movabs $37, %rax
	int $0x80
	mov %rax, 8*497(%rbx)
	mov 0x1598(%rbx), %rax
	mov %rax, 8*504(%rbx)

	mov 0x1588(%rbx), %edi
	xorl %esi, %esi
	lea 0x15a0(%rbx), %rdx
	movabs $16, %r10
	lea 0x15b0(%rbx), %r8
	movabs $38, %rax
	int $0x80
	mov %rax, 8*498(%rbx)
	mov 0x15b0(%rbx), %rax
	mov %rax, 8*505(%rbx)

	cmpq $16, 8*504(%rbx)
	jne socket_dup_data_done
	cmpq $16, 8*505(%rbx)
	jne socket_dup_data_done

	lea 0x1100(%rbx), %rsi
	lea 0x15a0(%rbx), %rdi
	mov $2, %rcx
socket_dup_data_cmp:
	mov (%rsi), %r8
	mov (%rdi), %r9
	cmp %r8, %r9
	jne user_fail
	add $8, %rsi
	add $8, %rdi
	loop socket_dup_data_cmp
	movq $1, 8*499(%rbx)
socket_dup_data_done:

	movq $1, 0x00(%rbx)
	int3

user_fail:
	movq $1, 0x00(%rbx)
	int3

axle_user_prog_end:
