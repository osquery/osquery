/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/linux/seccomp_events.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {

FLAG(bool,
     audit_allow_seccomp_events,
     false,
     "Allow the audit publisher to process seccomp events");

REGISTER(SeccompEventSubscriber, "event_subscriber", "seccomp_events");

namespace {

/// Extracts the specified integer key from the given <std::uint64_t,
/// std::string> unordered_map
bool GetStringFieldFromIntMap(
    std::string& value,
    const std::unordered_map<std::uint64_t, std::string>& fields,
    const std::uint64_t key,
    const std::string& default_value = std::string()) noexcept {
  auto it = fields.find(key);
  if (it == fields.end()) {
    value = default_value;
    return false;
  }

  value = it->second;
  return true;
}
} // namespace

Status SeccompEventSubscriber::init() {
  if (!FLAGS_audit_allow_seccomp_events) {
    return Status::failure("Seccomp subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&SeccompEventSubscriber::Callback, sc);

  return Status::success();
}

Status SeccompEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  QueryData data;
  auto status = processEvents(data, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  addBatch(data);

  return Status::success();
}

void SeccompEventSubscriber::parseEvent(const AuditEvent& event,
                                        Row& parsed_event) noexcept {
  const auto& event_data = boost::get<SeccompAuditEventData>(event.data);
  parsed_event["uptime"] = std::to_string(getUptime());
  std::uint64_t arch = 0;
  std::uint64_t value = 0;

  for (const auto& field : event_data.fields) {
    switch (field.second.which()) {
    case 0:
      // string field
      parsed_event[field.first] = boost::get<std::string>(field.second);
      break;
    case 1:
      // int field
      value = boost::get<const std::uint64_t>(field.second);
      if (field.first == "arch") {
        std::string symbolic_code_value = "";
        arch = value;
        parsed_event[field.first] =
            GetStringFieldFromIntMap(symbolic_code_value,
                                     SeccompEventSubscriber::arch_codes_map,
                                     value)
                ? symbolic_code_value
                : std::to_string(value) + "(unknown)";
        break;
      }
      if (field.first == "syscall" && arch == AUDIT_ARCH_X86_64) {
        std::string symbolic_code_value = "";
        parsed_event[field.first] =
            GetStringFieldFromIntMap(symbolic_code_value,
                                     SeccompEventSubscriber::syscall_x86_64_map,
                                     value)
                ? symbolic_code_value
                : std::to_string(value) + "(unknown)";
        break;
      }
      if (field.first == "syscall" && arch != AUDIT_ARCH_X86_64) {
        parsed_event[field.first] = std::to_string(value);
        break;
      }
      if (field.first == "code") {
        std::string symbolic_code_value = "";
        parsed_event[field.first] =
            GetStringFieldFromIntMap(
                symbolic_code_value,
                SeccompEventSubscriber::seccomp_actions_map,
                value)
                ? symbolic_code_value
                : std::to_string(value) + "(unknown)";
        break;
      }
      parsed_event[field.first] = UNSIGNED_BIGINT(value);
      break;
    default:
      continue;
    }
  }
}

Status SeccompEventSubscriber::processEvents(
    QueryData& data, const std::vector<AuditEvent>& event_list) noexcept {
  data.clear();

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::Seccomp) {
      continue;
    }

    if (event.record_list.size() != 1) {
      VLOG(1) << "SeccompEventSubscriber got record list";
      continue;
    }

    Row parsed_event;
    parseEvent(event, parsed_event);
    data.push_back(std::move(parsed_event));
  }

  return Status::success();
}

const std::unordered_map<std::uint64_t, std::string>
    SeccompEventSubscriber::seccomp_actions_map = {
        {SECCOMP_RET_KILL_PROCESS, "KILL_PROCESS"},
        {SECCOMP_RET_KILL_THREAD, "KILL_THREAD"},
        {SECCOMP_RET_TRAP, "TRAP"},
        {SECCOMP_RET_ERRNO, "ERRNO"},
        {SECCOMP_RET_TRACE, "TRACE"},
        {SECCOMP_RET_LOG, "LOG"},
        {SECCOMP_RET_ALLOW, "ALLOW"}};

const std::unordered_map<std::uint64_t, std::string>
    SeccompEventSubscriber::arch_codes_map = {
        {AUDIT_ARCH_X86_64, "X86_64"},
        {AUDIT_ARCH_AARCH64, "AARCH64"},
        {AUDIT_ARCH_ALPHA, "ALPHA"},
        {AUDIT_ARCH_ARM, "ARM"},
        {AUDIT_ARCH_ARMEB, "ARMEB"},
        {AUDIT_ARCH_CRIS, "CRIS"},
        {AUDIT_ARCH_FRV, "FRV"},
        {AUDIT_ARCH_I386, "I386"},
        {AUDIT_ARCH_IA64, "IA64"},
        {AUDIT_ARCH_M32R, "M32R"},
        {AUDIT_ARCH_M68K, "M68K"},
        {AUDIT_ARCH_MICROBLAZE, "MICROBLAZE"},
        {AUDIT_ARCH_MIPS, "MIPS"},
        {AUDIT_ARCH_MIPSEL, "MIPSEL"},
        {AUDIT_ARCH_MIPS64, "MIPS64"},
        {AUDIT_ARCH_MIPS64N32, "MIPS64N32"},
        {AUDIT_ARCH_MIPSEL64, "MIPSEL64"},
        {AUDIT_ARCH_MIPSEL64N32, "MIPSEL64N32"},
        {AUDIT_ARCH_OPENRISC, "OPENRISC"},
        {AUDIT_ARCH_PARISC, "PARISC"},
        {AUDIT_ARCH_PARISC64, "PARISC64"},
        {AUDIT_ARCH_PPC, "PPC"},
        {AUDIT_ARCH_PPC64, "PPC64"},
        {AUDIT_ARCH_PPC64LE, "PPC64LE"},
        {AUDIT_ARCH_S390, "S390"},
        {AUDIT_ARCH_S390X, "S390X"},
        {AUDIT_ARCH_SH, "SH"},
        {AUDIT_ARCH_SHEL, "SHEL"},
        {AUDIT_ARCH_SH64, "SH64"},
        {AUDIT_ARCH_SHEL64, "SHEL64"},
        {AUDIT_ARCH_SPARC, "SPARC"},
        {AUDIT_ARCH_SPARC64, "SPARC64"},
        {AUDIT_ARCH_TILEGX, "TILEGX"},
        {AUDIT_ARCH_TILEGX32, "TILEGX32"},
        {AUDIT_ARCH_TILEPRO, "TILEPRO"}};

const std::unordered_map<std::uint64_t, std::string>
    SeccompEventSubscriber::syscall_x86_64_map = {
        {0, "read"},
        {1, "write"},
        {2, "open"},
        {3, "close"},
        {4, "stat"},
        {5, "fstat"},
        {6, "lstat"},
        {7, "poll"},
        {8, "lseek"},
        {9, "mmap"},
        {10, "mprotect"},
        {11, "munmap"},
        {12, "brk"},
        {13, "rt_sigaction"},
        {14, "rt_sigprocmask"},
        {15, "rt_sigreturn"},
        {16, "ioctl"},
        {17, "pread64"},
        {18, "pwrite64"},
        {19, "readv"},
        {20, "writev"},
        {21, "access"},
        {22, "pipe"},
        {23, "select"},
        {24, "sched_yield"},
        {25, "mremap"},
        {26, "msync"},
        {27, "mincore"},
        {28, "madvise"},
        {29, "shmget"},
        {30, "shmat"},
        {31, "shmctl"},
        {32, "dup"},
        {33, "dup2"},
        {34, "pause"},
        {35, "nanosleep"},
        {36, "getitimer"},
        {37, "alarm"},
        {38, "setitimer"},
        {39, "getpid"},
        {40, "sendfile"},
        {41, "socket"},
        {42, "connect"},
        {43, "accept"},
        {44, "sendto"},
        {45, "recvfrom"},
        {46, "sendmsg"},
        {47, "recvmsg"},
        {48, "shutdown"},
        {49, "bind"},
        {50, "listen"},
        {51, "getsockname"},
        {52, "getpeername"},
        {53, "socketpair"},
        {54, "setsockopt"},
        {55, "getsockopt"},
        {56, "clone"},
        {57, "fork"},
        {58, "vfork"},
        {59, "execve"},
        {60, "exit"},
        {61, "wait4"},
        {62, "kill"},
        {63, "uname"},
        {64, "semget"},
        {65, "semop"},
        {66, "semctl"},
        {67, "shmdt"},
        {68, "msgget"},
        {69, "msgsnd"},
        {70, "msgrcv"},
        {71, "msgctl"},
        {72, "fcntl"},
        {73, "flock"},
        {74, "fsync"},
        {75, "fdatasync"},
        {76, "truncate"},
        {77, "ftruncate"},
        {78, "getdents"},
        {79, "getcwd"},
        {80, "chdir"},
        {81, "fchdir"},
        {82, "rename"},
        {83, "mkdir"},
        {84, "rmdir"},
        {85, "creat"},
        {86, "link"},
        {87, "unlink"},
        {88, "symlink"},
        {89, "readlink"},
        {90, "chmod"},
        {91, "fchmod"},
        {92, "chown"},
        {93, "fchown"},
        {94, "lchown"},
        {95, "umask"},
        {96, "gettimeofday"},
        {97, "getrlimit"},
        {98, "getrusage"},
        {99, "sysinfo"},
        {100, "times"},
        {101, "ptrace"},
        {102, "getuid"},
        {103, "syslog"},
        {104, "getgid"},
        {105, "setuid"},
        {106, "setgid"},
        {107, "geteuid"},
        {108, "getegid"},
        {109, "setpgid"},
        {110, "getppid"},
        {111, "getpgrp"},
        {112, "setsid"},
        {113, "setreuid"},
        {114, "setregid"},
        {115, "getgroups"},
        {116, "setgroups"},
        {117, "setresuid"},
        {118, "getresuid"},
        {119, "setresgid"},
        {120, "getresgid"},
        {121, "getpgid"},
        {122, "setfsuid"},
        {123, "setfsgid"},
        {124, "getsid"},
        {125, "capget"},
        {126, "capset"},
        {127, "rt_sigpending"},
        {128, "rt_sigtimedwait"},
        {129, "rt_sigqueueinfo"},
        {130, "rt_sigsuspend"},
        {131, "sigaltstack"},
        {132, "utime"},
        {133, "mknod"},
        {134, "uselib"},
        {135, "personality"},
        {136, "ustat"},
        {137, "statfs"},
        {138, "fstatfs"},
        {139, "sysfs"},
        {140, "getpriority"},
        {141, "setpriority"},
        {142, "sched_setparam"},
        {143, "sched_getparam"},
        {144, "sched_setscheduler"},
        {145, "sched_getscheduler"},
        {146, "sched_get_priority_max"},
        {147, "sched_get_priority_min"},
        {148, "sched_rr_get_interval"},
        {149, "mlock"},
        {150, "munlock"},
        {151, "mlockall"},
        {152, "munlockall"},
        {153, "vhangup"},
        {154, "modify_ldt"},
        {155, "pivot_root"},
        {156, "_sysctl"},
        {157, "prctl"},
        {158, "arch_prctl"},
        {159, "adjtimex"},
        {160, "setrlimit"},
        {161, "chroot"},
        {162, "sync"},
        {163, "acct"},
        {164, "settimeofday"},
        {165, "mount"},
        {166, "umount2"},
        {167, "swapon"},
        {168, "swapoff"},
        {169, "reboot"},
        {170, "sethostname"},
        {171, "setdomainname"},
        {172, "iopl"},
        {173, "ioperm"},
        {174, "create_module"},
        {175, "init_module"},
        {176, "delete_module"},
        {177, "get_kernel_syms"},
        {178, "query_module"},
        {179, "quotactl"},
        {180, "nfsservctl"},
        {181, "getpmsg"},
        {182, "putpmsg"},
        {183, "afs_syscall"},
        {184, "tuxcall"},
        {185, "security"},
        {186, "gettid"},
        {187, "readahead"},
        {188, "setxattr"},
        {189, "lsetxattr"},
        {190, "fsetxattr"},
        {191, "getxattr"},
        {192, "lgetxattr"},
        {193, "fgetxattr"},
        {194, "listxattr"},
        {195, "llistxattr"},
        {196, "flistxattr"},
        {197, "removexattr"},
        {198, "lremovexattr"},
        {199, "fremovexattr"},
        {200, "tkill"},
        {201, "time"},
        {202, "futex"},
        {203, "sched_setaffinity"},
        {204, "sched_getaffinity"},
        {205, "set_thread_area"},
        {206, "io_setup"},
        {207, "io_destroy"},
        {208, "io_getevents"},
        {209, "io_submit"},
        {210, "io_cancel"},
        {211, "get_thread_area"},
        {212, "lookup_dcookie"},
        {213, "epoll_create"},
        {214, "epoll_ctl_old"},
        {215, "epoll_wait_old"},
        {216, "remap_file_pages"},
        {217, "getdents64"},
        {218, "set_tid_address"},
        {219, "restart_syscall"},
        {220, "semtimedop"},
        {221, "fadvise64"},
        {222, "timer_create"},
        {223, "timer_settime"},
        {224, "timer_gettime"},
        {225, "timer_getoverrun"},
        {226, "timer_delete"},
        {227, "clock_settime"},
        {228, "clock_gettime"},
        {229, "clock_getres"},
        {230, "clock_nanosleep"},
        {231, "exit_group"},
        {232, "epoll_wait"},
        {233, "epoll_ctl"},
        {234, "tgkill"},
        {235, "utimes"},
        {236, "vserver"},
        {237, "mbind"},
        {238, "set_mempolicy"},
        {239, "get_mempolicy"},
        {240, "mq_open"},
        {241, "mq_unlink"},
        {242, "mq_timedsend"},
        {243, "mq_timedreceive"},
        {244, "mq_notify"},
        {245, "mq_getsetattr"},
        {246, "kexec_load"},
        {247, "waitid"},
        {248, "add_key"},
        {249, "request_key"},
        {250, "keyctl"},
        {251, "ioprio_set"},
        {252, "ioprio_get"},
        {253, "inotify_init"},
        {254, "inotify_add_watch"},
        {255, "inotify_rm_watch"},
        {256, "migrate_pages"},
        {257, "openat"},
        {258, "mkdirat"},
        {259, "mknodat"},
        {260, "fchownat"},
        {261, "futimesat"},
        {262, "newfstatat"},
        {263, "unlinkat"},
        {264, "renameat"},
        {265, "linkat"},
        {266, "symlinkat"},
        {267, "readlinkat"},
        {268, "fchmodat"},
        {269, "faccessat"},
        {270, "pselect6"},
        {271, "ppoll"},
        {272, "unshare"},
        {273, "set_robust_list"},
        {274, "get_robust_list"},
        {275, "splice"},
        {276, "tee"},
        {277, "sync_file_range"},
        {278, "vmsplice"},
        {279, "move_pages"},
        {280, "utimensat"},
        {281, "epoll_pwait"},
        {282, "signalfd"},
        {283, "timerfd_create"},
        {284, "eventfd"},
        {285, "fallocate"},
        {286, "timerfd_settime"},
        {287, "timerfd_gettime"},
        {288, "accept4"},
        {289, "signalfd4"},
        {290, "eventfd2"},
        {291, "epoll_create1"},
        {292, "dup3"},
        {293, "pipe2"},
        {294, "inotify_init1"},
        {295, "preadv"},
        {296, "pwritev"},
        {297, "rt_tgsigqueueinfo"},
        {298, "perf_event_open"},
        {299, "recvmmsg"},
        {300, "fanotify_init"},
        {301, "fanotify_mark"},
        {302, "prlimit64"},
        {303, "name_to_handle_at"},
        {304, "open_by_handle_at"},
        {305, "clock_adjtime"},
        {306, "syncfs"},
        {307, "sendmmsg"},
        {308, "setns"},
        {309, "getcpu"},
        {310, "process_vm_readv"},
        {311, "process_vm_writev"},
        {312, "kcmp"},
        {313, "finit_module"},
        {314, "sched_setattr"},
        {315, "sched_getattr"},
        {316, "renameat2"},
        {317, "seccomp"},
        {318, "getrandom"},
        {319, "memfd_create"},
        {320, "kexec_file_load"},
        {321, "bpf"},
        {322, "execveat"},
        {323, "userfaultfd"},
        {324, "membarrier"},
        {325, "mlock2"},
        {326, "copy_file_range"},
        {327, "preadv2"},
        {328, "pwritev2"},
        {329, "pkey_mprotect"},
        {330, "pkey_alloc"},
        {331, "pkey_free"},
        {332, "statx"},
        {333, "io_pgetevents"},
        {334, "rseq"}};
} // namespace osquery
