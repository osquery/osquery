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

static __always_inline void set_probe_error(struct process_event* event,
                                            __u32 reason_mask) {
  event->probe_error = 1;
  event->probe_error_mask |= reason_mask;
}

// -----------------------------------------------------------------------
// BPF helper function declarations
// -----------------------------------------------------------------------

// Map operations
static void* (*bpf_map_lookup_elem)(void* map,
                                    const void* key) = (void*)1;
static long (*bpf_map_update_elem)(void* map,
                                   const void* key,
                                   const void* value,
                                   __u64 flags) = (void*)2;
static long (*bpf_map_delete_elem)(void* map, const void* key) = (void*)3;

// Ring buffer
static void* (*bpf_ringbuf_reserve)(void* ringbuf,
                                    __u64 size,
                                    __u64 flags) = (void*)131;
static void (*bpf_ringbuf_submit)(void* data, __u64 flags) = (void*)132;

// Timing and identity
static __u64 (*bpf_ktime_get_ns)(void) = (void*)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void*)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void*)15;
static long (*bpf_get_current_comm)(void* buf, __u32 size_of_buf) = (void*)16;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void*)80;

// User-space memory read helpers
static long (*bpf_probe_read_user_str)(void* dst,
                                       __u32 size,
                                       const void* unsafe_ptr) = (void*)114;
static long (*bpf_probe_read_user)(void* dst,
                                   __u32 size,
                                   const void* unsafe_ptr) = (void*)112;

// Kernel-space memory read helpers (used for CO-RE struct access)
static long (*bpf_probe_read_kernel)(void* dst,
                                     __u32 size,
                                     const void* unsafe_ptr) = (void*)113;
static long (*bpf_probe_read_kernel_str)(void* dst,
                                         __u32 size,
                                         const void* unsafe_ptr) = (void*)115;

// Task struct access
static unsigned long (*bpf_get_current_task)(void) = (void*)35;

// Valid license strings seem to be shared with kernel modules:
// https://docs.kernel.org/process/license-rules.html#id1 Apache-2.0 is not
// included in those so we specify just GPL
char LICENSE[] SEC("license") = "GPL";

// Map definition macros (BTF-style, required for bpftool gen skeleton)
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val)* name

// -----------------------------------------------------------------------
// Map definitions
// -----------------------------------------------------------------------

// Ring buffer for output events
struct {
  __uint(type, 27); // BPF_MAP_TYPE_RINGBUF
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hash map storing in-flight events keyed by pid_tgid.
// Populated in sys_enter_execve; consumed and deleted in sys_exit_execve.
struct {
  __uint(type, 1); // BPF_MAP_TYPE_HASH
  __uint(max_entries, 10240);
  __type(key, __u64);
  __type(value, struct process_event);
} inflight_events SEC(".maps");

// Per-CPU scratch buffer for constructing events without hitting the 512-byte
// BPF stack limit (struct process_event is ~1100 bytes).
struct {
  __uint(type, 6); // BPF_MAP_TYPE_PERCPU_ARRAY
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct process_event);
} event_scratch SEC(".maps");

// -----------------------------------------------------------------------
// Minimal CO-RE kernel struct shadows.
//
// __attribute__((preserve_access_index)) instructs clang to emit a BTF
// relocation for every field access on these types.  libbpf resolves the
// relocations against the running kernel's BTF at load time, so field
// offsets are always correct regardless of kernel version.
//
// Field names MUST match the kernel's BTF names exactly.
// -----------------------------------------------------------------------

struct qstr {
  union {
    struct {
      __u32 hash;
      __u32 len;
    };
    __u64 hash_len;
  };
  const unsigned char* name;
} __attribute__((preserve_access_index));

struct dentry {
  struct dentry* d_parent;
  struct qstr d_name;
} __attribute__((preserve_access_index));

struct vfsmount {
  struct dentry* mnt_root;
} __attribute__((preserve_access_index));

struct path {
  struct vfsmount* mnt;
  struct dentry* dentry;
} __attribute__((preserve_access_index));

struct fs_struct {
  int users;
  struct path pwd;
} __attribute__((preserve_access_index));

struct file;

struct mm_struct {
  unsigned long arg_start;
  unsigned long arg_end;
  struct file* exe_file;
} __attribute__((preserve_access_index));

struct file {
  struct path f_path;
} __attribute__((preserve_access_index));

struct task_struct {
  __u32 tgid; // Thread group ID (= userspace process PID)
  struct fs_struct* fs;
  struct mm_struct* mm;
  struct task_struct* real_parent;
} __attribute__((preserve_access_index));

// -----------------------------------------------------------------------
// Tracepoint context structures
// -----------------------------------------------------------------------

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

struct syscall_exit_execve_args {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  long syscall_nr;
  long ret; // Return value: 0 on success, -errno on failure
};

// -----------------------------------------------------------------------
// CWD path helper
//
// Walks the dentry chain upward from the task's current directory,
// collecting path components into a fixed on-stack array
// (MAX_CWD_DEPTH × MAX_CWD_COMPONENT = 8 × 32 = 256 bytes), then
// concatenates them in root-to-leaf order into event->cwd.
//
// Uses CO-RE relocations (preserve_access_index structs above) so field
// offsets are patched to the running kernel's layout at load time.
//
// Falls back to "/" if any kernel read fails.
// -----------------------------------------------------------------------
#define MAX_CWD_DEPTH 8
#define MAX_CWD_COMPONENT 32

// noinline creates a BPF subprogram with its own independent 512-byte stack
// frame.  The names[8][32] scratch buffer (256 bytes) plus other locals would
// overflow the caller's frame if this were inlined.
static __attribute__((noinline)) void fill_cwd(struct process_event* event,
                                               struct task_struct* task) {
  event->cwd[0] = '/';
  event->cwd[1] = '\0';

  struct fs_struct* fs;
  if (bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs) < 0 || !fs) {
    set_probe_error(event, PROCESS_EVENT_PROBE_ERR_CWD_FS);
    return;
  }

  struct dentry* dentry;
  struct vfsmount* mnt;
  if (bpf_probe_read_kernel(&dentry, sizeof(dentry), &fs->pwd.dentry) < 0 ||
      bpf_probe_read_kernel(&mnt, sizeof(mnt), &fs->pwd.mnt) < 0 ||
      !dentry || !mnt) {
    set_probe_error(event, PROCESS_EVENT_PROBE_ERR_CWD_DENTRY);
    return;
  }

  struct dentry* mnt_root = 0;
  bpf_probe_read_kernel(&mnt_root, sizeof(mnt_root), &mnt->mnt_root);

  // Collect path components from leaf (cwd) toward root.
  // 8 × 32 = 256 bytes — fits comfortably within the 512-byte BPF stack
  // alongside the other frame variables.
  char names[MAX_CWD_DEPTH][MAX_CWD_COMPONENT];
  int count = 0;

#pragma unroll
  for (int i = 0; i < MAX_CWD_DEPTH; i++) {
    if (!dentry)
      break;

    struct dentry* parent;
    if (bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent) < 0)
      break;

    // Stop at the mount-point root or the filesystem root.
    if (parent == dentry || dentry == mnt_root)
      break;

    const unsigned char* name_ptr;
    if (bpf_probe_read_kernel(
            &name_ptr, sizeof(name_ptr), &dentry->d_name.name) < 0)
      break;

    long n = bpf_probe_read_kernel_str(
        &names[count][0], MAX_CWD_COMPONENT, name_ptr);
    if (n <= 0)
      break;

    count++;
    dentry = parent;
  }

  if (count == 0) {
    return; // Already at root — "/" default is correct.
  }

  // Concatenate components in reverse (root-most first) into event->cwd.
  // __u64 pos: the break check `if (pos >= N)` is a direct 64-bit compare,
  // letting the verifier constrain pos in the fall-through path (same
  // reasoning as total_len in the args loop below).
  __u64 pos = 0;
  event->cwd[pos++] = '/';

#pragma unroll
  for (int i = MAX_CWD_DEPTH - 1; i >= 0; i--) {
    if (i >= count)
      continue;

    // Ensure there is room for this component (MAX_CWD_COMPONENT bytes) plus
    // one extra byte for the following '/' or final '\0'.
    // After this check the verifier knows pos <= MAX_PATH_LEN - MAX_CWD_COMPONENT - 1,
    // so event->cwd[pos .. pos+MAX_CWD_COMPONENT] is provably in-bounds.
    if (pos >= MAX_PATH_LEN - MAX_CWD_COMPONENT)
      break;

    // Copy the name directly from the BPF stack (PTR_TO_STACK) into the CWD
    // buffer (PTR_TO_MAP_VALUE).  This replaces a character-by-character loop
    // whose per-iteration state explosion caused the verifier complexity limit
    // to be exceeded (processed 1 000 001 insns).
    // bpf_probe_read_kernel_str accepts ARG_ANYTHING for its source.
    long len = bpf_probe_read_kernel_str(
        event->cwd + pos, MAX_CWD_COMPONENT, names[i]);
    if (len <= 0 || len > MAX_CWD_COMPONENT)
      break;

    pos += (unsigned long)(len - 1); // len includes the null terminator

    // Separator between components (not after the innermost one).
    if (i > 0 && pos < MAX_PATH_LEN - 1) {
      event->cwd[pos++] = '/';
    }
  }

  if (pos < MAX_PATH_LEN) {
    event->cwd[pos] = '\0';
  }
}

// -----------------------------------------------------------------------
// Cmdline recovery helper (sys_exit fallback)
//
// Reads the current task mm->arg_start..arg_end range after a successful
// execve and reconstructs a space-separated command line into event->args.
// This avoids races with short-lived processes that may exit before userspace
// can recover /proc/<pid>/cmdline.
// -----------------------------------------------------------------------
static __attribute__((noinline)) int fill_args_from_mm(struct process_event* event,
                                                       struct task_struct* task) {
  struct mm_struct* mm = 0;
  if (bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm) < 0 || !mm) {
    set_probe_error(event, PROCESS_EVENT_PROBE_ERR_MM_READ);
    return 0;
  }

  unsigned long arg_start = 0;
  unsigned long arg_end = 0;
  if (bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &mm->arg_start) < 0 ||
      bpf_probe_read_kernel(&arg_end, sizeof(arg_end), &mm->arg_end) < 0 ||
      arg_end <= arg_start) {
    set_probe_error(event, PROCESS_EVENT_PROBE_ERR_MM_ARG_RANGE);
    return 0;
  }

  __u64 total_len = 0;
  unsigned long cursor = arg_start;
  event->args[0] = '\0';

#pragma unroll
  for (int i = 0; i < 16; i++) {
    if (total_len > MAX_ARGS_LEN - MAX_SINGLE_ARG_LEN || cursor >= arg_end) {
      break;
    }

    long len = bpf_probe_read_user_str(
        &event->args[total_len], MAX_SINGLE_ARG_LEN, (const void*)cursor);
    if (len <= 0) {
      break;
    }

    // A single '\0' means we reached the terminating delimiter.
    if (len == 1) {
      break;
    }

    total_len += (unsigned int)len;
    cursor += (unsigned long)len;

    // Replace the copied null terminator with a space between argv tokens.
    if (total_len > 0 && total_len < MAX_ARGS_LEN) {
      event->args[total_len - 1] = ' ';
    }
  }

  if (total_len > 0 && total_len <= MAX_ARGS_LEN) {
    event->args[total_len - 1] = '\0';
    return 1;
  }

  return 0;
}

// -----------------------------------------------------------------------
// Executable path recovery helper (sys_exit fallback)
//
// Reads task->mm->exe_file->f_path and reconstructs an absolute-ish path
// within the current mount using dentry walking, similar to CWD recovery.
// -----------------------------------------------------------------------
static __attribute__((noinline)) int fill_path_from_mm_exe_file(
    struct process_event* event, struct task_struct* task) {
  struct mm_struct* mm = 0;
  if (bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm) < 0 || !mm) {
    return 0;
  }

  struct file* exe_file = 0;
  if (bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file) < 0 ||
      !exe_file) {
    return 0;
  }

  struct dentry* dentry = 0;
  struct vfsmount* mnt = 0;
  if (bpf_probe_read_kernel(&dentry, sizeof(dentry), &exe_file->f_path.dentry) <
          0 ||
      bpf_probe_read_kernel(&mnt, sizeof(mnt), &exe_file->f_path.mnt) < 0 ||
      !dentry || !mnt) {
    return 0;
  }

  struct dentry* mnt_root = 0;
  bpf_probe_read_kernel(&mnt_root, sizeof(mnt_root), &mnt->mnt_root);

  char names[MAX_CWD_DEPTH][MAX_CWD_COMPONENT];
  int count = 0;

#pragma unroll
  for (int i = 0; i < MAX_CWD_DEPTH; i++) {
    if (!dentry)
      break;

    struct dentry* parent = 0;
    if (bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent) < 0)
      break;

    if (parent == dentry || dentry == mnt_root)
      break;

    const unsigned char* name_ptr = 0;
    if (bpf_probe_read_kernel(
            &name_ptr, sizeof(name_ptr), &dentry->d_name.name) < 0)
      break;

    long n = bpf_probe_read_kernel_str(
        &names[count][0], MAX_CWD_COMPONENT, name_ptr);
    if (n <= 0)
      break;

    count++;
    dentry = parent;
  }

  __u64 pos = 0;
  event->path[pos++] = '/';

#pragma unroll
  for (int i = MAX_CWD_DEPTH - 1; i >= 0; i--) {
    if (i >= count)
      continue;

    if (pos >= MAX_PATH_LEN - MAX_CWD_COMPONENT)
      break;

    long len = bpf_probe_read_kernel_str(
        event->path + pos, MAX_CWD_COMPONENT, names[i]);
    if (len <= 0 || len > MAX_CWD_COMPONENT)
      break;

    pos += (unsigned long)(len - 1);

    if (i > 0 && pos < MAX_PATH_LEN - 1) {
      event->path[pos++] = '/';
    }
  }

  if (pos < MAX_PATH_LEN) {
    event->path[pos] = '\0';
  }

  // Success if we recovered something beyond just '/'.
  return (event->path[0] == '/' && event->path[1] != '\0');
}

// -----------------------------------------------------------------------
// Tracepoint: sys_enter_execve
//
// Captures all userspace-readable fields (path, argv, uid/gid, cwd, …)
// and parks the partially-filled event in inflight_events, keyed by
// pid_tgid.  The event is completed and emitted by handle_execve_exit.
// -----------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct syscall_enter_execve_args* ctx) {
  // Use per-CPU scratch to build the event without stack overflow.
  // BPF stack is limited to 512 bytes; struct process_event is ~1100 bytes.
  __u32 scratch_key = 0;
  struct process_event* event =
      bpf_map_lookup_elem(&event_scratch, &scratch_key);
  if (!event) {
    return 0;
  }

  // Record the start timestamp first for accurate duration measurement.
  event->timestamp = bpf_ktime_get_ns();

  // Capture process and thread IDs.
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->pid = pid_tgid >> 32;
  event->tid = pid_tgid & 0xFFFFFFFF;

  // Capture parent PID via CO-RE task struct access.
  event->ppid = 0;
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct task_struct* parent_task;
  if (bpf_probe_read_kernel(
          &parent_task, sizeof(parent_task), &task->real_parent) == 0 &&
      parent_task) {
    __u32 ppid;
    if (bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent_task->tgid) == 0) {
      event->ppid = ppid;
    }
  }

  // Capture user and group IDs.
  __u64 uid_gid = bpf_get_current_uid_gid();
  event->uid = uid_gid & 0xFFFFFFFF;
  event->gid = uid_gid >> 32;

  // Capture cgroup ID.
  event->cgroup_id = bpf_get_current_cgroup_id();

  // Filled by the exit handler; initialise to safe defaults.
  event->exit_code = 0;
  event->duration = 0;
  event->probe_error = 0;
  event->probe_error_mask = 0;

  // Read command name from the task struct.
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Read binary path from userspace.
  if (bpf_probe_read_user_str(event->path, sizeof(event->path),
                               ctx->filename) < 0) {
    set_probe_error(event, PROCESS_EVENT_PROBE_ERR_PATH_READ);
  }

  // Read command line arguments.
  // The verifier-safe pattern: bound total_len with a constant-size check so
  // that &event->args[total_len] + MAX_SINGLE_ARG_LEN is provably in-bounds.
  // Using a variable size for bpf_probe_read_user_str would require the verifier
  // to track off + space_left == MAX_ARGS_LEN symbolically, which it cannot do.
  const char* const* argv = ctx->argv;
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
    const char* arg = 0;

    // Read argv[i] pointer using an explicit byte offset. This avoids
    // relying on compiler-generated addressing for &argv[i], which can be
    // fragile in BPF programs depending on kernel/clang combinations.
    __u64 arg_ptr_addr = (__u64)argv + ((__u64)i * sizeof(arg));
    if (bpf_probe_read_user(&arg, sizeof(arg), (const void*)arg_ptr_addr) < 0) {
      set_probe_error(event, PROCESS_EVENT_PROBE_ERR_ARGV_PTR_READ);
      break;
    }

    if (!arg) {
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
      set_probe_error(event, PROCESS_EVENT_PROBE_ERR_ARGV_STR_READ);
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

  // Read current working directory by walking the kernel dentry chain.
  fill_cwd(event, task);

  // Park the partially-filled event; the exit handler completes and submits it.
  bpf_map_update_elem(&inflight_events, &pid_tgid, event, 0 /* BPF_ANY */);

  return 0;
}

// -----------------------------------------------------------------------
// Tracepoint: sys_exit_execve
//
// Retrieves the in-flight event built by handle_execve_enter, fills in
// the actual exit code and syscall duration, copies it to the ring
// buffer, and submits it.  Always cleans up the inflight_events entry.
// -----------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(struct syscall_exit_execve_args* ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct process_event* event =
      bpf_map_lookup_elem(&inflight_events, &pid_tgid);
  if (!event) {
    // No matching enter event — dropped or race condition.
    return 0;
  }

  // Complete the event with fields only available at syscall exit.
  event->exit_code = ctx->ret;
  event->duration = bpf_ktime_get_ns() - event->timestamp;

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  int path_recovered = 0;
  int cmdline_recovered = 0;

  // If the entry-time filename probe failed, try recovering executable path
  // from task->mm->exe_file at syscall exit.
  if (ctx->ret == 0 && event->path[0] == '\0') {
    path_recovered = fill_path_from_mm_exe_file(event, task);
  }

  // If argv probing failed at sys_enter, recover cmdline from the newly
  // installed mm arg range while still in process context.
  if (ctx->ret == 0 && event->probe_error) {
    cmdline_recovered = fill_args_from_mm(event, task);
  }

  // Fallback for processes whose userspace exec args could not be read at
  // entry time (probe_error=1, e.g. setuid binaries or special memory
  // layouts).  After a successful execve the kernel has already replaced the
  // process image, so bpf_get_current_comm() now returns the new program's
  // comm (e.g. "man").  Use it to populate args so json_cmdline shows at
  // least ["man"] instead of [].
  if (ctx->ret == 0 && event->probe_error && event->args[0] == '\0') {
    bpf_get_current_comm(event->args, TASK_COMM_LEN);
    if (event->args[0] != '\0') {
      cmdline_recovered = 1;
    }
  }

  // If any cmdline fallback recovered usable data, clear cmdline-related
  // probe errors.
  if (ctx->ret == 0 && cmdline_recovered) {
    event->probe_error_mask &= ~(PROCESS_EVENT_PROBE_ERR_ARGV_PTR_READ |
                                 PROCESS_EVENT_PROBE_ERR_ARGV_STR_READ |
                                 PROCESS_EVENT_PROBE_ERR_MM_READ |
                                 PROCESS_EVENT_PROBE_ERR_MM_ARG_RANGE);

    if (event->probe_error_mask == 0U) {
      event->probe_error = 0;
    }
  }

  // If executable path recovery succeeded, clear path-read probe error.
  if (ctx->ret == 0 && path_recovered) {
    event->probe_error_mask &= ~PROCESS_EVENT_PROBE_ERR_PATH_READ;

    if (event->probe_error_mask == 0U) {
      event->probe_error = 0;
    }
  }

  // Copy the completed event to the ring buffer and submit it.
  struct process_event* rb_event =
      bpf_ringbuf_reserve(&events, sizeof(*rb_event), 0);
  if (rb_event) {
    // bpf_probe_read_kernel copies from the map-value pointer (trusted kernel
    // memory) into the ring-buffer reservation.  Struct assignment generates
    // an implicit memcpy which is not supported by the BPF back-end.
    bpf_probe_read_kernel(rb_event, sizeof(*rb_event), event);
    bpf_ringbuf_submit(rb_event, 0);
  }

  // Always clean up the inflight entry regardless of ring-buffer availability.
  bpf_map_delete_elem(&inflight_events, &pid_tgid);

  return 0;
}
