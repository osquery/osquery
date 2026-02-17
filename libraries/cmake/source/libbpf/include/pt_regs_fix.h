#ifndef PT_REGS_FIX_H
#define PT_REGS_FIX_H

/* Manually define struct pt_regs for x86_64 as it is missing from toolchain headers */
#ifndef __KERNEL__
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};
#endif

#ifndef bpf_user_pt_regs_t
typedef struct pt_regs bpf_user_pt_regs_t;
#endif

#endif // PT_REGS_FIX_H
