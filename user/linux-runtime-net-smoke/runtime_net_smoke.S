.section .rodata
success_message:
    .ascii "runtime net ok\n"
success_message_len = . - success_message
ping_message:
    .ascii "ping"
pong_message:
    .ascii "pong"

listen_addr:
    .short 2
    .byte 0x10, 0x92
    .byte 0x7f, 0x00, 0x00, 0x01
    .quad 0

one_word:
    .long 1
optlen_word:
    .long 4

.section .bss
    .balign 16
listener_addr_len:
    .skip 4
client_local_len:
    .skip 4
client_peer_len:
    .skip 4
accepted_peer_len:
    .skip 4
sockopt_len:
    .skip 4
listener_addr_buf:
    .skip 16
client_local_buf:
    .skip 16
client_peer_buf:
    .skip 16
accepted_peer_buf:
    .skip 16
read_buf:
    .skip 16
sockopt_value:
    .skip 4

.section .text
.global _start
.type _start, @function
_start:
    movl $41, %eax
    movl $2, %edi
    movl $1, %esi
    xorl %edx, %edx
    syscall
    test %rax, %rax
    js fail_1
    mov %eax, %r12d

    movl $54, %eax
    mov %r12d, %edi
    movl $1, %esi
    movl $2, %edx
    lea one_word(%rip), %r10
    movl $4, %r8d
    syscall
    test %rax, %rax
    jne fail_2

    movl $49, %eax
    mov %r12d, %edi
    lea listen_addr(%rip), %rsi
    movl $16, %edx
    syscall
    test %rax, %rax
    jne fail_3

    movl $16, listener_addr_len(%rip)
    movl $51, %eax
    mov %r12d, %edi
    lea listener_addr_buf(%rip), %rsi
    lea listener_addr_len(%rip), %rdx
    syscall
    test %rax, %rax
    jne fail_4
    cmpw $2, listener_addr_buf(%rip)
    jne fail_5
    cmpw $0x9210, listener_addr_buf+2(%rip)
    jne fail_6
    movl listener_addr_buf+4(%rip), %eax
    cmpl $0x0100007f, %eax
    jne fail_7

    movl $50, %eax
    mov %r12d, %edi
    movl $4, %esi
    syscall
    test %rax, %rax
    jne fail_8

    movl $41, %eax
    movl $2, %edi
    movl $1, %esi
    xorl %edx, %edx
    syscall
    test %rax, %rax
    js fail_9
    mov %eax, %r13d

    movl $54, %eax
    mov %r13d, %edi
    movl $6, %esi
    movl $1, %edx
    lea one_word(%rip), %r10
    movl $4, %r8d
    syscall
    test %rax, %rax
    jne fail_10

    movl $42, %eax
    mov %r13d, %edi
    lea listen_addr(%rip), %rsi
    movl $16, %edx
    syscall
    test %rax, %rax
    jne fail_11

    movl $16, client_peer_len(%rip)
    movl $52, %eax
    mov %r13d, %edi
    lea client_peer_buf(%rip), %rsi
    lea client_peer_len(%rip), %rdx
    syscall
    test %rax, %rax
    jne fail_12
    cmpw $2, client_peer_buf(%rip)
    jne fail_13
    cmpw $0x9210, client_peer_buf+2(%rip)
    jne fail_14

    movl $16, accepted_peer_len(%rip)
    movl $288, %eax
    mov %r12d, %edi
    lea accepted_peer_buf(%rip), %rsi
    lea accepted_peer_len(%rip), %rdx
    xorl %r10d, %r10d
    syscall
    test %rax, %rax
    js fail_15
    mov %eax, %r14d
    cmpw $2, accepted_peer_buf(%rip)
    jne fail_16
    cmpw $0, accepted_peer_buf+2(%rip)
    je fail_17

    movl $16, client_local_len(%rip)
    movl $51, %eax
    mov %r13d, %edi
    lea client_local_buf(%rip), %rsi
    lea client_local_len(%rip), %rdx
    syscall
    test %rax, %rax
    jne fail_18
    cmpw $2, client_local_buf(%rip)
    jne fail_19
    cmpw $0, client_local_buf+2(%rip)
    je fail_20
    movl client_local_buf+4(%rip), %eax
    cmpl $0x0100007f, %eax
    jne fail_21
    movl client_local_buf(%rip), %eax
    cmpl accepted_peer_buf(%rip), %eax
    jne fail_22
    movl client_local_buf+4(%rip), %eax
    cmpl accepted_peer_buf+4(%rip), %eax
    jne fail_23

    movl $4, %edx
    lea ping_message(%rip), %rsi
    mov %r13d, %edi
    movl $1, %eax
    syscall
    cmpq $4, %rax
    jne fail_26

    movl $4, %edx
    lea read_buf(%rip), %rsi
    mov %r14d, %edi
    movl $0, %eax
    syscall
    cmpq $4, %rax
    jne fail_27
    movl read_buf(%rip), %eax
    cmpl ping_message(%rip), %eax
    jne fail_28

    movl $4, %edx
    lea pong_message(%rip), %rsi
    mov %r14d, %edi
    movl $1, %eax
    syscall
    cmpq $4, %rax
    jne fail_29

    movl $4, %edx
    lea read_buf(%rip), %rsi
    mov %r13d, %edi
    movl $0, %eax
    syscall
    cmpq $4, %rax
    jne fail_30
    movl read_buf(%rip), %eax
    cmpl pong_message(%rip), %eax
    jne fail_31

    movl $48, %eax
    mov %r13d, %edi
    movl $1, %esi
    syscall
    test %rax, %rax
    jne fail_32

    movl $4, %edx
    lea read_buf(%rip), %rsi
    mov %r14d, %edi
    movl $0, %eax
    syscall
    test %rax, %rax
    jne fail_33

    mov %r14d, %edi
    movl $3, %eax
    syscall
    test %rax, %rax
    jne fail_34
    mov %r13d, %edi
    movl $3, %eax
    syscall
    test %rax, %rax
    jne fail_35
    mov %r12d, %edi
    movl $3, %eax
    syscall
    test %rax, %rax
    jne fail_36

    movl $1, %edi
    lea success_message(%rip), %rsi
    movl $success_message_len, %edx
    movl $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_37

    xorl %edi, %edi
    movl $60, %eax
    syscall

fail_1:  mov $1, %edi;  jmp fail_exit
fail_2:  mov $2, %edi;  jmp fail_exit
fail_3:  mov $3, %edi;  jmp fail_exit
fail_4:  mov $4, %edi;  jmp fail_exit
fail_5:  mov $5, %edi;  jmp fail_exit
fail_6:  mov $6, %edi;  jmp fail_exit
fail_7:  mov $7, %edi;  jmp fail_exit
fail_8:  mov $8, %edi;  jmp fail_exit
fail_9:  mov $9, %edi;  jmp fail_exit
fail_10: mov $10, %edi; jmp fail_exit
fail_11: mov $11, %edi; jmp fail_exit
fail_12: mov $12, %edi; jmp fail_exit
fail_13: mov $13, %edi; jmp fail_exit
fail_14: mov $14, %edi; jmp fail_exit
fail_15: mov $15, %edi; jmp fail_exit
fail_16: mov $16, %edi; jmp fail_exit
fail_17: mov $17, %edi; jmp fail_exit
fail_18: mov $18, %edi; jmp fail_exit
fail_19: mov $19, %edi; jmp fail_exit
fail_20: mov $20, %edi; jmp fail_exit
fail_21: mov $21, %edi; jmp fail_exit
fail_22: mov $22, %edi; jmp fail_exit
fail_23: mov $23, %edi; jmp fail_exit
fail_24: mov $24, %edi; jmp fail_exit
fail_25: mov $88, %edi; jmp fail_exit
fail_26: mov $26, %edi; jmp fail_exit
fail_27: mov $27, %edi; jmp fail_exit
fail_28: mov $28, %edi; jmp fail_exit
fail_29: mov $29, %edi; jmp fail_exit
fail_30: mov $30, %edi; jmp fail_exit
fail_31: mov $31, %edi; jmp fail_exit
fail_32: mov $32, %edi; jmp fail_exit
fail_33: mov $33, %edi; jmp fail_exit
fail_34: mov $34, %edi; jmp fail_exit
fail_35: mov $35, %edi; jmp fail_exit
fail_36: mov $36, %edi; jmp fail_exit
fail_37: mov $37, %edi; jmp fail_exit

fail_exit:
    movl $60, %eax
    syscall
