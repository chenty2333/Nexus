typedef unsigned long u64;

__attribute__((noreturn)) static void sys_exit(int code) {
    __asm__ volatile("syscall" : : "a"(60), "D"((long)code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static u64 *auxv_start(u64 *stack) {
    u64 argc = *stack++;
    stack += argc;
    stack += 1;
    while (*stack != 0) {
        stack += 1;
    }
    return stack + 1;
}

__attribute__((noreturn, visibility("hidden"))) void dynamic_tls_interp_start(u64 *stack) {
    u64 *aux = auxv_start(stack);
    u64 entry = 0;
    for (;;) {
        if (aux[0] == 0) {
            sys_exit(40);
        }
        if (aux[0] == 9) {
            entry = aux[1];
            break;
        }
        aux += 2;
    }
    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "jmp *%1\n\t"
        :
        : "r"(stack), "r"(entry)
        : "memory");
    __builtin_unreachable();
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov %rsp, %rdi\n\t"
        "andq $-16, %rsp\n\t"
        "call dynamic_tls_interp_start\n\t");
}
