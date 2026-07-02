/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifndef OSQUERY_EVENTS_LINUX_BPF_BPF_PROCESS_EVENTS_H_
#define OSQUERY_EVENTS_LINUX_BPF_BPF_PROCESS_EVENTS_H_

#include <linux/types.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_ARGS_LEN 512

// Event structure shared between BPF program and userspace
struct process_event {
  __u64 timestamp; // BPF timestamp (ktime_get_ns)
  __u64 pid; // Process ID
  __u64 tid; // Thread ID
  __u64 ppid; // Parent PID
  __u64 uid; // User ID
  __u64 gid; // Group ID
  __u32 cgroup_id; // Cgroup ID
  __s64 exit_code; // Exit code from execve syscall
  __u64 duration; // Syscall duration in nanoseconds
  __u8 probe_error; // Error flag

  char comm[TASK_COMM_LEN]; // Command name (from task_struct)
  char path[MAX_PATH_LEN]; // Binary path
  char cwd[MAX_PATH_LEN]; // Current working directory
  char args[MAX_ARGS_LEN]; // Command line arguments (space-separated)
};

#endif // OSQUERY_EVENTS_LINUX_BPF_BPF_PROCESS_EVENTS_H_
