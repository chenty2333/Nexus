typedef unsigned char u8;
typedef unsigned long u64;

__thread int main_tls_value = 0x12345678;

static long sys_write(int fd, const void *buf, unsigned long len) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(1), "D"((long)fd), "S"(buf), "d"(len)
                     : "rcx", "r11", "memory");
    return ret;
}

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
        if (kind == 0) {
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

static int random_has_entropy(const u8 *bytes) {
    for (int i = 0; i < 16; i += 1) {
        if (bytes[i] != 0) {
            return 1;
        }
    }
    return 0;
}

__attribute__((noreturn, visibility("hidden"))) void dynamic_runtime_start(u64 *stack) {
    static const char ok[] = "dynamic runtime ok\n";
    u64 aux = 0;

    if (main_tls_value != 0x12345678) {
        sys_exit(2);
    }
    main_tls_value = 0x87654321;
    if (main_tls_value != 0x87654321) {
        sys_exit(3);
    }
    if (!find_aux(stack, 7, &aux) || aux == 0) {
        sys_exit(4);
    }
    if (!find_aux(stack, 23, &aux) || aux != 0) {
        sys_exit(5);
    }
    if (!find_aux(stack, 25, &aux) || aux == 0 || !random_has_entropy((const u8 *)aux)) {
        sys_exit(6);
    }
    if (!find_aux(stack, 31, &aux)
        || !string_equals((const char *)aux, "/bin/linux-dynamic-runtime-main")) {
        sys_exit(7);
    }
    if (!find_aux(stack, 15, &aux) || !string_equals((const char *)aux, "x86_64")) {
        sys_exit(8);
    }
    if (!find_aux(stack, 16, &aux)) {
        sys_exit(9);
    }
    if (!find_aux(stack, 26, &aux)) {
        sys_exit(10);
    }
    if (!find_aux(stack, 17, &aux) || aux != 100) {
        sys_exit(11);
    }
    if (!find_aux(stack, 11, &aux) || aux != 0) {
        sys_exit(12);
    }
    if (!find_aux(stack, 12, &aux) || aux != 0) {
        sys_exit(13);
    }
    if (!find_aux(stack, 13, &aux) || aux != 0) {
        sys_exit(14);
    }
    if (!find_aux(stack, 14, &aux) || aux != 0) {
        sys_exit(15);
    }
    if (sys_write(1, ok, sizeof(ok) - 1) != (long)(sizeof(ok) - 1)) {
        sys_exit(16);
    }
    sys_exit(0);
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov %rsp, %rdi\n\t"
        "andq $-16, %rsp\n\t"
        "call dynamic_runtime_start\n\t");
}
