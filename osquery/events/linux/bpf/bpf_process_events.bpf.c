/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// BPF program for tracking process execution events (execve syscalls)

// Only define what we absolutely need
#define SEC(NAME) __attribute__((section(NAME), used))

#include "bpf_process_events.h"

// Maximum bytes read per individual argument. Must be a compile-time constant
// so the BPF verifier can prove that &event->args[total_len] + MAX_SINGLE_ARG_LEN
// never exceeds the end of the args[] buffer.
#define MAX_SINGLE_ARG_LEN 64

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

  // Read command line arguments.
  // The verifier-safe pattern: bound total_len with a constant-size check so
  // that &event->args[total_len] + MAX_SINGLE_ARG_LEN is provably in-bounds.
  // Using a variable size for bpf_probe_read_user_str would require the verifier
  // to track off + space_left == MAX_ARGS_LEN symbolically, which it cannot do.
  const char *const *argv = ctx->argv;
  // __u64 is critical here: the break check `if (total_len > N)` compiles to a
  // direct 64-bit compare (`if r9 > N goto break`), which lets the verifier
  // constrain r9 itself in the fall-through path.  With `unsigned int`, the
  // compiler inserts `<<= 32; >>= 32` zero-extension before the compare,
  // creating a derived register (r1) that loses identity with r9 — so the
  // verifier cannot back-propagate the constraint to r9, and by iteration 9
  // r9's umax hits 512, making 601 + 512 + 64 = 1177 > sz(1120) → EACCES.
  __u64 total_len = 0;
  event->args[0] = '\0';
#pragma unroll
  for (int i = 0; i < 16; i++) {
    const char *arg;
    if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0 || !arg) {
      break;
    }

    // Break if there is no room for another MAX_SINGLE_ARG_LEN-byte argument.
    // After this check the verifier knows total_len <= MAX_ARGS_LEN - MAX_SINGLE_ARG_LEN,
    // so the write of MAX_SINGLE_ARG_LEN bytes at &event->args[total_len] is in-bounds.
    if (total_len > MAX_ARGS_LEN - MAX_SINGLE_ARG_LEN) {
      break;
    }

    long len = bpf_probe_read_user_str(
        &event->args[total_len], MAX_SINGLE_ARG_LEN, arg);
    if (len <= 0) {
      break;
    }

    total_len += (unsigned int)len;

    // Replace the null terminator with a space to concatenate arguments.
    if (total_len > 0 && total_len < MAX_ARGS_LEN) {
      event->args[total_len - 1] = ' ';
    }
  }

  // Null-terminate the concatenated arguments string.
  if (total_len > 0 && total_len <= MAX_ARGS_LEN) {
    event->args[total_len - 1] = '\0';
  }

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
