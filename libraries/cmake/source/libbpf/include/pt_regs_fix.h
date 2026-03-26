#ifndef PT_REGS_FIX_H
#define PT_REGS_FIX_H

/* This header is force-included for all libbpf compilation units.
 *
 * It ensures bpf_user_pt_regs_t is fully defined before any source file
 * includes our bpf_perf_event.h stub (which uses it as a struct field).
 *
 * Include asm/ptrace.h now to get the complete struct definition.
 * When source files later include <linux/ptrace.h> -> <asm/ptrace.h>,
 * the header guards prevent any redefinition.
 *
 * On x86/x86_64, asm/ptrace.h defines struct pt_regs.
 * On aarch64, asm/ptrace.h defines struct user_pt_regs. */
#include <asm/ptrace.h>

#ifndef bpf_user_pt_regs_t
#if defined(__aarch64__)
typedef struct user_pt_regs bpf_user_pt_regs_t;
#else
typedef struct pt_regs bpf_user_pt_regs_t;
#endif
#endif

#endif // PT_REGS_FIX_H
