/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// BPF program for tracking process execution events (execve syscalls)
// Minimal version compatible with clang 9 - no linux/ header dependencies

// Basic type definitions needed for BPF
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

// Only define what we absolutely need - avoid including anything that pulls in
// linux/types.h
#define SEC(NAME) __attribute__((section(NAME), used))

#include "bpf_process_events.h"

// BPF helper function declarations (from bpf_helpers.h but without includes)
static void* (*bpf_ringbuf_reserve)(void* ringbuf,
                                    __u64 size,
                                    __u64 flags) = (void*)131;
static void (*bpf_ringbuf_submit)(void* data, __u64 flags) = (void*)132;
static __u64 (*bpf_ktime_get_ns)(void) = (void*)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void*)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void*)15;
static long (*bpf_get_current_comm)(void* buf, __u32 size_of_buf) = (void*)16;
static long (*bpf_probe_read_user_str)(void* dst,
                                       __u32 size,
                                       const void* unsafe_ptr) = (void*)114;
static long (*bpf_probe_read_user)(void* dst,
                                   __u32 size,
                                   const void* unsafe_ptr) = (void*)112;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void*)80;

// Valid license strings seem to be shared with kernel modules:
// https://docs.kernel.org/process/license-rules.html#id1 Apache-2.0 is not
// included in those so we specify just GPL
char LICENSE[] SEC("license") = "GPL";

// Ring buffer map definition using BTF-style macros (required for bpftool gen
// skeleton)
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val)* name

struct {
  __uint(type, 27); // BPF_MAP_TYPE_RINGBUF
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint context structure
struct syscall_enter_execve_args {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  long syscall_nr;
  const char* filename;
  const char* const* argv;
  const char* const* envp;
};

// Tracepoint for execve syscall entry
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct syscall_enter_execve_args* ctx) {
  // Reserve space in ring buffer
  struct process_event* event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  // Capture timestamp
  event->timestamp = bpf_ktime_get_ns();

  // Capture process IDs
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->pid = pid_tgid >> 32;
  event->tid = pid_tgid & 0xFFFFFFFF;
  event->ppid = 0; // Would need task_struct access

  // Capture user and group IDs
  __u64 uid_gid = bpf_get_current_uid_gid();
  event->uid = uid_gid & 0xFFFFFFFF;
  event->gid = uid_gid >> 32;

  // Capture cgroup ID
  event->cgroup_id = bpf_get_current_cgroup_id();

  // Read command name
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Read binary path
  bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename);

  /*
  // Read command line arguments
  const char *const *argv = ctx->argv;
  unsigned int total_len = 0;
  for (int i = 0; i < 16; i++) {
    const char *arg;
    // Read the pointer to the i-th argument from user space
    if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0 || !arg) {
      break;
    }

    // Use a masked offset to help the verifier bound memory access
    unsigned int off = total_len & 511;
    unsigned int space_left = MAX_ARGS_LEN - off;

    // Read the argument string directly into the ring buffer
    // The verifier can now see that off + space_left is always 512
    long len = bpf_probe_read_user_str(&event->args[off], space_left, arg);
    if (len <= 0) {
      break;
    }

    unsigned int ulen = (unsigned int)len;
    // Update total_len for the next iteration
    total_len += ulen;

    // Replace null terminator with space to concatenate next argument
    if (total_len > 0 && total_len < MAX_ARGS_LEN) {
        event->args[(total_len - 1) & 511] = ' ';
    }
  }

  // Ensure the entire arguments string is null-terminated
  if (total_len > 0 && total_len <= MAX_ARGS_LEN) {
      event->args[(total_len - 1) & 511] = '\0';
  }
      */

  // Set defaults
  event->cwd[0] = '/';
  event->cwd[1] = '\0';
  event->exit_code = 0;
  event->duration = 0;
  event->probe_error = 0;

  // Submit event
  bpf_ringbuf_submit(event, 0);

  return 0;
}
