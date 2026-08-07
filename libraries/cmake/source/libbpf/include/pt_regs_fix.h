#ifndef PT_REGS_FIX_H
#define PT_REGS_FIX_H

/* This header is force-included for all libbpf compilation units.
 *
 * It pre-declares bpf_user_pt_regs_t so that our bpf_perf_event.h stub can
 * use it. The struct itself is completed by the #include <asm/ptrace.h> in
 * bpf_perf_event.h, which fires after each source file's own standard library
 * includes are already set up (avoiding conflicts with glibc internals).
 *
 * On x86/x86_64, asm/ptrace.h defines struct pt_regs.
 * On aarch64, asm/ptrace.h defines struct user_pt_regs. */
#ifndef bpf_user_pt_regs_t
#if defined(__aarch64__)
typedef struct user_pt_regs bpf_user_pt_regs_t;
#else
typedef struct pt_regs bpf_user_pt_regs_t;
#endif
#endif

#endif // PT_REGS_FIX_H
