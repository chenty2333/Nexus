typedef unsigned long u64;

__attribute__((used, section(".tdata"))) static u64 interp_tls_init = 0x1122334455667788ull;
__attribute__((used, section(".tbss"))) static u64 interp_tls_zero;

enum {
    AT_NULL = 0,
    AT_ENTRY = 9,
    AT_PLATFORM = 15,
    AT_HWCAP = 16,
    AT_HWCAP2 = 26,
};

enum {
    INTERP_TLS_INIT_OFFSET = -20,
    INTERP_TLS_ZERO_OFFSET = -12,
};

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

static int find_aux(u64 *stack, u64 key, u64 *value) {
    u64 *aux = auxv_start(stack);
    for (;;) {
        u64 kind = aux[0];
        u64 current = aux[1];
        if (kind == AT_NULL) {
            return 0;
        }
        if (kind == key) {
            *value = current;
            return 1;
        }
        aux += 2;
    }
}

static int string_equals(const char *lhs, const char *rhs) {
    for (;;) {
        if (*lhs != *rhs) {
            return 0;
        }
        if (*lhs == '\0') {
            return 1;
        }
        lhs += 1;
        rhs += 1;
    }
}

static u64 read_fs_qword(int offset) {
    u64 value;
    switch (offset) {
    case INTERP_TLS_INIT_OFFSET:
        __asm__ volatile("movq %%fs:%c1, %0" : "=r"(value) : "i"(INTERP_TLS_INIT_OFFSET));
        return value;
    case INTERP_TLS_ZERO_OFFSET:
        __asm__ volatile("movq %%fs:%c1, %0" : "=r"(value) : "i"(INTERP_TLS_ZERO_OFFSET));
        return value;
    default:
        sys_exit(90);
    }
}

__attribute__((noreturn, visibility("hidden"))) void dynamic_runtime_interp_start(u64 *stack) {
    u64 entry = 0;
    u64 aux = 0;
    if (read_fs_qword(INTERP_TLS_INIT_OFFSET) != 0x1122334455667788ull) {
        sys_exit(40);
    }
    if (read_fs_qword(INTERP_TLS_ZERO_OFFSET) != 0) {
        sys_exit(41);
    }
    if (!find_aux(stack, AT_PLATFORM, &aux) || !string_equals((const char *)aux, "x86_64")) {
        sys_exit(42);
    }
    if (!find_aux(stack, AT_HWCAP, &aux)) {
        sys_exit(43);
    }
    if (!find_aux(stack, AT_HWCAP2, &aux)) {
        sys_exit(44);
    }
    if (!find_aux(stack, AT_ENTRY, &entry) || entry == 0) {
        sys_exit(45);
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
        "call dynamic_runtime_interp_start\n\t");
}
