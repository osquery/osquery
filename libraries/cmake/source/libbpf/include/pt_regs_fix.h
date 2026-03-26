#ifndef PT_REGS_FIX_H
#define PT_REGS_FIX_H

/* Define bpf_user_pt_regs_t for BPF/USDT usage when the toolchain's
 * linux/bpf_perf_event.h does not provide it.
 *
 * On x86/x86_64, asm/ptrace.h defines struct pt_regs in userspace and
 * bpf_user_pt_regs_t aliases it.
 *
 * On aarch64, the kernel exports struct user_pt_regs (not struct pt_regs)
 * to userspace via asm/ptrace.h, so bpf_user_pt_regs_t aliases that instead. */
#ifndef bpf_user_pt_regs_t
#if defined(__aarch64__)
typedef struct user_pt_regs bpf_user_pt_regs_t;
#else
typedef struct pt_regs bpf_user_pt_regs_t;
#endif
#endif

#endif // PT_REGS_FIX_H
