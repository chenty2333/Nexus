typedef unsigned char u8;
typedef unsigned long u64;

__thread int main_tls_value = 0x10203040;

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

__attribute__((noreturn, visibility("hidden"))) void dynamic_pie_start(u64 *stack) {
    static const char ok[] = "dynamic pie ok\n";
    u64 aux = 0;

    if (main_tls_value != 0x10203040) {
        sys_exit(2);
    }
    main_tls_value = 0x40302010;
    if (main_tls_value != 0x40302010) {
        sys_exit(3);
    }
    if (!find_aux(stack, 7, &aux) || aux == 0) {
        sys_exit(4);
    }
    if (!find_aux(stack, 9, &aux) || aux < 0x100000000ull) {
        sys_exit(5);
    }
    if (!find_aux(stack, 31, &aux)
        || !string_equals((const char *)aux, "/bin/linux-dynamic-pie-main")) {
        sys_exit(6);
    }
    if (!find_aux(stack, 15, &aux) || !string_equals((const char *)aux, "x86_64")) {
        sys_exit(7);
    }
    if (sys_write(1, ok, sizeof(ok) - 1) != (long)(sizeof(ok) - 1)) {
        sys_exit(8);
    }
    sys_exit(0);
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov %rsp, %rdi\n\t"
        "andq $-16, %rsp\n\t"
        "call dynamic_pie_start\n\t");
}
