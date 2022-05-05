/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>

#include <mach-o/dyld_images.h>

#include <array>
#include <map>
#include <set>

#include <boost/algorithm/string.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/rows/processes.h>

#include <chrono>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// The maximum number of expected memory regions per process.
#define MAX_MEMORY_MAPS 512

#define CPU_TIME_RATIO 1000000
#define START_TIME_RATIO 1000000000
#define NSECS_IN_USEC 1000

// Process states are as defined in sys/proc.h
// SIDL   (1) Process being created by fork
// SRUN   (2) Currently runnable
// SSLEEP (3) Sleeping on an address
// SSTOP  (4) Process debugging or suspension
// SZOMB  (5) Awaiting collection by parent
const char kProcessStateMapping[] = {' ', 'I', 'R', 'S', 'T', 'Z'};

/**
 * @brief Use process APIs for quick process path access.
 *
 * This has a secondary effect if the process is run as root. It can inspect
 * the process memory for the first region to find the EXE path. This helps
 * if the process's program was deleted.
 *
 * @param pid The pid requested.
 */
static std::string getProcPath(int pid);

std::set<int> getProcList(const QueryContext& context) {
  std::set<int> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      if (pid >= 0) {
        pidlist.insert(pid);
      }
    }
    return pidlist;
  }

  int bufsize = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
  if (bufsize <= 0) {
    VLOG(1) << "An error occurred retrieving the process list";
    return pidlist;
  }

  // Use twice the number of PIDs returned to handle races.
  std::vector<pid_t> pids(2 * bufsize);

  bufsize = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), 2 * bufsize);
  if (bufsize <= 0) {
    VLOG(1) << "An error occurred retrieving the process list";
    return pidlist;
  }

  size_t num_pids = bufsize / sizeof(pid_t);
  for (size_t i = 0; i < num_pids; ++i) {
    // If the pid is negative, it doesn't represent a real process so
    // continue the iterations so that we don't add it to the results set
    if (pids[i] < 0) {
      continue;
    }
    pidlist.insert(pids[i]);
  }
  return pidlist;
}

struct proc_cred {
  uint32_t parent{0};
  uint32_t group{0};
  uint32_t status{0};
  int32_t nice{0};
  struct {
    uid_t uid{0};
    gid_t gid{0};
  } real, effective, saved;
};

inline bool genProcCred(QueryContext& context,
                        int pid,
                        proc_cred& cred,
                        ProcessesRow& r) {
  struct proc_bsdinfo bsdinfo;
  struct proc_bsdshortinfo bsdinfo_short;

  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &bsdinfo, PROC_PIDTBSDINFO_SIZE) ==
      PROC_PIDTBSDINFO_SIZE) {
    cred.parent = bsdinfo.pbi_ppid;
    cred.group = bsdinfo.pbi_pgid;
    cred.status = bsdinfo.pbi_status;
    cred.nice = bsdinfo.pbi_nice;
    cred.real.uid = bsdinfo.pbi_ruid;
    cred.real.gid = bsdinfo.pbi_rgid;
    cred.effective.uid = bsdinfo.pbi_uid;
    cred.effective.gid = bsdinfo.pbi_gid;
    cred.saved.uid = bsdinfo.pbi_svuid;
    cred.saved.gid = bsdinfo.pbi_svgid;
  } else if (proc_pidinfo(pid,
                          PROC_PIDT_SHORTBSDINFO,
                          1,
                          &bsdinfo_short,
                          PROC_PIDT_SHORTBSDINFO_SIZE) ==
             PROC_PIDT_SHORTBSDINFO_SIZE) {
    cred.parent = bsdinfo_short.pbsi_ppid;
    cred.group = bsdinfo_short.pbsi_pgid;
    cred.status = bsdinfo_short.pbsi_status;
    cred.real.uid = bsdinfo_short.pbsi_ruid;
    cred.real.gid = bsdinfo_short.pbsi_rgid;
    cred.effective.uid = bsdinfo_short.pbsi_uid;
    cred.effective.gid = bsdinfo_short.pbsi_gid;
    cred.saved.uid = bsdinfo_short.pbsi_svuid;
    cred.saved.gid = bsdinfo_short.pbsi_svgid;
  } else {
    return false;
  }

  r.parent_col = cred.parent;
  r.pgroup_col = cred.group;
  r.state_col = (1 <= cred.status && cred.status <= 5)
                    ? kProcessStateMapping[cred.status]
                    : '?';
  r.nice_col = cred.nice;
  r.uid_col = cred.real.uid;
  r.gid_col = cred.real.gid;
  r.euid_col = cred.effective.uid;
  r.egid_col = cred.effective.gid;
  r.suid_col = cred.saved.uid;
  r.sgid_col = cred.saved.gid;

  return true;
}

// Get the max args space
static inline int genMaxArgs() {
  static int argmax = 0;

  if (argmax == 0) {
    int mib[2] = {CTL_KERN, KERN_ARGMAX};
    size_t size = sizeof(argmax);
    if (sysctl(mib, 2, &argmax, &size, nullptr, 0) == -1) {
      VLOG(1) << "An error occurred retrieving the max argument size";
      return 0;
    }
  }
  return argmax;
}

void genProcRootAndCWD(const QueryContext& context, int pid, ProcessesRow& r) {
  if (!context.isAnyColumnUsed(ProcessesRow::CWD | ProcessesRow::ROOT)) {
    return;
  }

  struct proc_vnodepathinfo pathinfo;
  if (proc_pidinfo(
          pid, PROC_PIDVNODEPATHINFO, 0, &pathinfo, sizeof(pathinfo)) ==
      sizeof(pathinfo)) {
    if (context.isAnyColumnUsed(ProcessesRow::CWD) &&
        pathinfo.pvi_cdir.vip_vi.vi_stat.vst_dev != 0) {
      r.cwd_col = std::string(pathinfo.pvi_cdir.vip_path);
    }

    if (context.isAnyColumnUsed(ProcessesRow::ROOT) &&
        pathinfo.pvi_rdir.vip_vi.vi_stat.vst_dev != 0) {
      r.root_col = std::string(pathinfo.pvi_rdir.vip_path);
    }
  }
}

void genProcNamePathAndOnDisk(const QueryContext& context,
                              int pid,
                              const struct proc_cred& cred,
                              ProcessesRow& r) {
  if (!context.isAnyColumnUsed(ProcessesRow::NAME | ProcessesRow::PATH |
                               ProcessesRow::ON_DISK)) {
    return;
  }

  std::string path;
  if (pid == 0) {
    path = "";
    if (context.isAnyColumnUsed(ProcessesRow::NAME)) {
      // For some reason not even proc_name gives back a name for kernel_task
      r.name_col = "kernel_task";
    }
  } else if (cred.status != 5) { // If the process is not a Zombie, try to
                                 // find the path and name.
    path = getProcPath(pid);
    if (context.isAnyColumnUsed(ProcessesRow::NAME)) {
      // OS X proc_name only returns 16 bytes, use the basename of the path.
      r.name_col = fs::path(path).filename().string();
    }
  } else {
    path = "";
    if (context.isAnyColumnUsed(ProcessesRow::NAME)) {
      std::vector<char> name(17);
      proc_name(pid, name.data(), 16);
      r.name_col = std::string(name.data());
    }
  }
  r.path_col = path;

  if (!context.isAnyColumnUsed(ProcessesRow::ON_DISK)) {
    return;
  }

  // If the path of the executable that started the process is available and
  // the path exists on disk, set on_disk to 1. If the path is not
  // available, set on_disk to -1. If, and only if, the path of the
  // executable is available and the file does NOT exist on disk, set on_disk
  // to 0.
  if (path.empty()) {
    r.on_disk_col = -1;
  } else if (pathExists(path)) {
    r.on_disk_col = 1;
  } else {
    r.on_disk_col = 0;
  }
}

void genProcNumThreads(QueryContext& context, int pid, ProcessesRow& r) {
  if (!context.isAnyColumnUsed(ProcessesRow::THREADS)) {
    return;
  }

  struct proc_taskinfo task_info;
  int status =
      proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task_info, sizeof(task_info));
  if (status == sizeof(task_info)) {
    r.threads_col = task_info.pti_threadnum;
  } else {
    r.threads_col = -1;
  }
}

void genProcUniquePid(QueryContext& context, int pid, ProcessesRow& r) {
  if (!context.isAnyColumnUsed(ProcessesRow::UPID | ProcessesRow::UPPID)) {
    return;
  }

  struct proc_uniqidentifierinfo {
    uint8_t p_uuid[16];
    uint64_t p_uniqueid;
    uint64_t p_puniqueid;
    uint64_t p_reserve2;
    uint64_t p_reserve3;
    uint64_t p_reserve4;
  };

  struct proc_uniqidentifierinfo uniqidinfo;
  int status = proc_pidinfo(pid, 17, 0, &uniqidinfo, sizeof(uniqidinfo));
  if (status == sizeof(uniqidinfo)) {
    r.upid_col = uniqidinfo.p_uniqueid;
    r.uppid_col = uniqidinfo.p_puniqueid;
  } else {
    r.upid_col = -1;
    r.uppid_col = -1;
  }
}

void genProcArch(QueryContext& context, int pid, ProcessesRow& r) {
  if (!context.isAnyColumnUsed(ProcessesRow::CPU_TYPE |
                               ProcessesRow::CPU_SUBTYPE |
                               ProcessesRow::TRANSLATED)) {
    return;
  }

  // default the translated column to 0
  r.translated_col = 0;

  struct proc_archinfo {
    cpu_type_t p_cputype;
    cpu_subtype_t p_cpusubtype;
  };

  struct proc_archinfo archinfo {
    0, 0
  };
  // 19 is the flavor for this API call. It is normally used by Apple code
  // under the constant PROC_PIDARCHINFO but is unexported
  size_t status = proc_pidinfo(pid, 19, 0, &archinfo, sizeof(archinfo));
  if (status == sizeof(archinfo)) {
    r.cpu_type_col = archinfo.p_cputype;
    r.cpu_subtype_col = archinfo.p_cpusubtype;
  } else {
    r.cpu_type_col = -1;
    r.cpu_subtype_col = -1;
  }

  if (archinfo.p_cputype == CPU_TYPE_ARM64) {
    struct kinfo_proc kinfo {};
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    size_t size = sizeof(kinfo);

    if (sysctl(mib, 4, &kinfo, &size, nullptr, 0) != 0 ||
        size < sizeof(kinfo)) {
      r.translated_col = -1;
      return;
    }

    // proc_bsdinfo also has pbi_flags, but that seems to be not always
    // populated, instead kinfo_proc works better to get at the process flags
    // and check whether P_TRANSLATED is one of the flags
    if (kinfo.kp_proc.p_flag & P_TRANSLATED) {
      r.translated_col = 1;
    }
  }
}

bool parseProcCmdline(std::string& args, size_t len) {
  // argc is the first value.
  int nargs = 0;
  if (len < sizeof(nargs)) {
    return false;
  }

  memcpy(&nargs, args.data(), sizeof(nargs));
  // Skip the executable path.
  size_t start = sizeof(nargs);
  size_t nul = args.find('\0', start);
  if (nul == std::string::npos) {
    return false;
  }

  start = args.find_first_not_of('\0', nul);
  if (start == std::string::npos) {
    return false;
  }

  // Skip argc and the executable.
  args.erase(0, start);
  start = 0;
  while (nargs-- && nul != std::string::npos) {
    nul = args.find('\0', start);
    args[nul] = ' ';
    start = nul + 1;
  }

  // Unhandled error.
  if (nargs != -1) {
    return false;
  }

  // Trim the environment data.
  args.erase(nul);
  return true;
}

std::map<std::string, std::string> getProcEnv(int pid, size_t argmax) {
  std::map<std::string, std::string> env;
  std::unique_ptr<char[]> pprocargs{new char[argmax]};
  char* procargs = pprocargs.get();
  int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
  if (sysctl(mib, 3, procargs, &argmax, nullptr, 0) == -1 || argmax == 0) {
    return env;
  }

  // The number of arguments is an integer in front of the result buffer.
  int nargs = 0;
  memcpy(&nargs, procargs, sizeof(nargs));
  // Walk the \0-tokenized list of arguments until reaching the returned 'max'
  // number of arguments or the number appended to the front.
  const char* current_arg = &procargs[0] + sizeof(nargs);
  // Then skip the exec/program name.
  auto exec_name = std::string(current_arg);
  current_arg += exec_name.size() + 1;
  while (current_arg < &procargs[argmax]) {
    // Skip optional null-character padding.
    if (*current_arg == '\0') {
      current_arg++;
      continue;
    }

    auto string_arg = std::string(current_arg);
    if (string_arg.size() > 0) {
      if (nargs > 0) {
        nargs--;
      } else {
        size_t idx = string_arg.find_first_of("=");
        if (idx != std::string::npos && idx > 0) {
          env[string_arg.substr(0, idx)] = string_arg.substr(idx + 1);
        }
      }
    }
    current_arg += string_arg.size() + 1;
  }
  return env;
}

void genProcCmdline(const QueryContext& context, int pid, ProcessesRow& r) {
  if (!context.isAnyColumnUsed(ProcessesRow::CMDLINE)) {
    return;
  }

  size_t len = 0;
  int mib[] = {CTL_KERN, KERN_PROCARGS2, pid};
  // Estimate the size.
  if (sysctl(mib, 3, nullptr, &len, nullptr, 0) != 0) {
    return;
  }

  len++;
  std::string args(len, 0);
  // Request content.
  if (sysctl(mib, 3, &args[0], &len, nullptr, 0) != 0) {
    return;
  }

  if (parseProcCmdline(args, len)) {
    r.cmdline_col = std::move(args);
  }
}

void genProcResourceUsage(const QueryContext& context,
                          int pid,
                          ProcessesRow& r) {
  if (!context.isAnyColumnUsed(
          ProcessesRow::WIRED_SIZE | ProcessesRow::RESIDENT_SIZE |
          ProcessesRow::TOTAL_SIZE | ProcessesRow::USER_TIME |
          ProcessesRow::SYSTEM_TIME | ProcessesRow::DISK_BYTES_READ |
          ProcessesRow::DISK_BYTES_WRITTEN | ProcessesRow::START_TIME)) {
    return;
  }

  struct rusage_info_v2 rusage_info_data;
  int status =
      proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t*)&rusage_info_data);
  // proc_pid_rusage returns -1 if it was unable to gather information
  if (status == 0) {
    // Initialize time conversions.
    static mach_timebase_info_data_t time_base;
    if (time_base.denom == 0) {
      mach_timebase_info(&time_base);
    }

    // size/memory information
    r.wired_size_col = rusage_info_data.ri_wired_size;
    r.resident_size_col = rusage_info_data.ri_resident_size;
    r.total_size_col = rusage_info_data.ri_phys_footprint;

    // time information
    r.user_time_col =
        ((rusage_info_data.ri_user_time * time_base.numer) / time_base.denom) /
        CPU_TIME_RATIO;
    r.system_time_col = ((rusage_info_data.ri_system_time * time_base.numer) /
                         time_base.denom) /
                        CPU_TIME_RATIO;

    // disk i/o information
    r.disk_bytes_read_col = rusage_info_data.ri_diskio_bytesread;
    r.disk_bytes_written_col = rusage_info_data.ri_diskio_byteswritten;

    if (context.isAnyColumnUsed(ProcessesRow::START_TIME)) {
      uint64_t const absoluteTime = mach_absolute_time();
      auto const process_age = std::chrono::nanoseconds{
          (absoluteTime - rusage_info_data.ri_proc_start_abstime) *
          time_base.numer / time_base.denom};

      r.start_time_col =
          std::time(nullptr) -
          std::chrono::duration_cast<std::chrono::seconds>(process_age).count();
    }
  } else {
    r.wired_size_col = -1;
    r.resident_size_col = -1;
    r.total_size_col = -1;
    r.user_time_col = -1;
    r.system_time_col = -1;
    r.start_time_col = -1;
  }
}

TableRows genProcesses(QueryContext& context) {
  TableRows results;

  auto pidlist = getProcList(context);
  for (const auto& pid : pidlist) {
    ProcessesRow* r = new ProcessesRow();
    r->pid_col = pid;

    genProcCmdline(context, pid, *r);

    // The process relative root and current working directory.
    genProcRootAndCWD(context, pid, *r);

    proc_cred cred;
    if (!genProcCred(context, pid, cred, *r)) {
      continue;
    }

    genProcNamePathAndOnDisk(context, pid, cred, *r);

    // systems usage and time information
    genProcResourceUsage(context, pid, *r);

    genProcNumThreads(context, pid, *r);

    genProcUniquePid(context, pid, *r);

    genProcArch(context, pid, *r);

    std::unique_ptr<TableRow> tr(r);
    results.push_back(std::move(tr));
  }

  return results;
}

QueryData genProcessEnvs(QueryContext& context) {
  QueryData results;

  auto pidlist = getProcList(context);
  int argmax = genMaxArgs();
  for (const auto& pid : pidlist) {
    auto envs = getProcEnv(pid, argmax);
    for (const auto& env : envs) {
      Row r;
      r["pid"] = INTEGER(pid);
      r["key"] = env.first;
      r["value"] = env.second;
      results.push_back(r);
    }
  }

  return results;
}

void genMemoryRegion(int pid,
                     const vm_address_t& address,
                     const vm_size_t& size,
                     struct vm_region_submap_info_64& info,
                     const std::map<vm_address_t, std::string>& libraries,
                     QueryData& results) {
  Row r;
  r["pid"] = INTEGER(pid);

  char addr_str[17] = {0};
  sprintf(addr_str, "%016lx", address);
  r["start"] = "0x" + std::string(addr_str);
  sprintf(addr_str, "%016lx", address + size);
  r["end"] = "0x" + std::string(addr_str);

  char perms[5] = {0};
  sprintf(perms,
          "%c%c%c",
          (info.protection & VM_PROT_READ) ? 'r' : '-',
          (info.protection & VM_PROT_WRITE) ? 'w' : '-',
          (info.protection & VM_PROT_EXECUTE) ? 'x' : '-');
  // Mimic Linux permissions reporting.
  r["permissions"] = std::string(perms) + 'p';

  char filename[PATH_MAX] = {0};
  // Eventually we'll arrive at dynamic memory COW regions.
  // OS X will return a dyld_shared_cache[...] substitute alias.
  int bytes = proc_regionfilename(pid, address, filename, sizeof(filename));

  if (info.share_mode == SM_COW && info.ref_count == 1) {
    // (psutil) Treat single reference SM_COW as SM_PRIVATE
    info.share_mode = SM_PRIVATE;
  }

  if (bytes == 0 || filename[0] == 0) {
    switch (info.share_mode) {
    case SM_COW:
      r["path"] = "[cow]";
      break;
    case SM_PRIVATE:
      r["path"] = "[private]";
      break;
    case SM_EMPTY:
      r["path"] = "[null]";
      break;
    case SM_SHARED:
    case SM_TRUESHARED:
      r["path"] = "[shared]";
      break;
    case SM_PRIVATE_ALIASED:
      r["path"] = "[private_aliased]";
      break;
    case SM_SHARED_ALIASED:
      r["path"] = "[shared_aliased]";
      break;
    default:
      r["path"] = "[unknown]";
    }
    // Labeling all non-path regions pseudo is not 100% appropriate.
    // Practically, pivoting on non-meta (actual) paths is helpful.
    r["pseudo"] = "1";
  } else {
    // The share mode is not a mutex for having a filled-in path.
    r["path"] = std::string(filename);
    r["pseudo"] = "0";
  }

  // Necessary to do an unaligned read without triggering UB
  memory_object_offset_t offset;
  memcpy(&offset, &info.offset, sizeof(offset));

  r["offset"] = INTEGER(offset);
  r["device"] = INTEGER(info.object_id);

  // Fields not applicable to OS X maps.
  r["inode"] = "0";

  // Increment the address/region request offset.
  results.push_back(r);

  // Submaps or offsets into regions may contain libraries mapped from the
  // dyld cache.
  for (const auto& library : libraries) {
    if (library.first > address && library.first < (address + size)) {
      r["offset"] = INTEGER(info.offset + (library.first - address));
      r["path"] = library.second;
      r["pseudo"] = "0";
      results.push_back(r);
    }
  }
}

static bool readProcessMemory(const mach_port_t& task,
                              const vm_address_t& from,
                              const vm_size_t& size,
                              vm_address_t to) {
  vm_size_t bytes;
  auto status = vm_read_overwrite(task, from, size, to, &bytes);
  if (status != KERN_SUCCESS) {
    return false;
  }

  if (bytes != size) {
    return false;
  }
  return true;
}

void genProcessLibraries(const mach_port_t& task,
                         std::map<vm_address_t, std::string>& libraries) {
  struct task_dyld_info dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  auto status =
      task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
  if (status != KERN_SUCCESS) {
    // Cannot request dyld information for pid (permissions, invalid).
    return;
  }

  // The info struct is a pointer to another process's virtual space.
  auto all_info = (struct dyld_all_image_infos*)dyld_info.all_image_info_addr;
  uint64_t image_offset = (uint64_t)all_info;
  if (dyld_info.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64) {
    // Only support 64bit process images.
    return;
  }

  // Skip the 32-bit integer version field.
  image_offset += sizeof(uint32_t);
  uint32_t info_array_count = 0;
  // Read the process's 32-bit integer infoArrayCount (number of libraries).
  if (!readProcessMemory(task,
                         image_offset,
                         sizeof(uint32_t),
                         (vm_address_t)&info_array_count)) {
    return;
  }

  image_offset += sizeof(uint32_t);
  vm_address_t info_array = 0;
  // Read the process's infoArray address field.
  if (!readProcessMemory(task,
                         image_offset,
                         sizeof(vm_address_t),
                         (vm_address_t)&info_array)) {
    return;
  }

  // Loop over the array of dyld_image_info structures.
  // Read the process-mapped address and pointer to the library path.
  for (uint32_t i = 0; i < info_array_count; i++) {
    dyld_image_info image;
    if (!readProcessMemory(task,
                           info_array + (i * sizeof(struct dyld_image_info)),
                           sizeof(dyld_image_info),
                           (vm_address_t)&image)) {
      return;
    }

    // It's possible to optimize for smaller reads by chucking the memory reads.
    char path[PATH_MAX] = {0};
    if (!readProcessMemory(task,
                           (vm_address_t)image.imageFilePath,
                           PATH_MAX,
                           (vm_address_t)&path)) {
      continue;
    }

    // Keep the process-mapped address as the library index.
    libraries[(vm_address_t)image.imageLoadAddress] = path;
  }
}

void genProcessMemoryMap(int pid, QueryData& results, bool exe_only = false) {
  mach_port_t task = MACH_PORT_NULL;
  kern_return_t status = task_for_pid(mach_task_self(), pid, &task);
  if (status != KERN_SUCCESS) {
    // Cannot request memory map for pid (permissions, invalid).
    return;
  }

  // Create a map of library paths from the dyld cache.
  std::map<vm_address_t, std::string> libraries;
  if (!exe_only) {
    genProcessLibraries(task, libraries);
  }

  // Use address offset (starting at 0) to count memory maps.
  vm_address_t address = 0;
  size_t map_count = 0;
  uint32_t depth = 0;

  while (map_count++ < MAX_MEMORY_MAPS) {
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

    vm_size_t size = 0;
    status =
        vm_region_recurse_64(task,
                             &address,
                             &size,
                             &depth,
                             reinterpret_cast<vm_region_recurse_info_t>(&info),
                             &count);

    if (status == KERN_INVALID_ADDRESS) {
      // Reached the end of the memory map.
      break;
    }

    if (info.is_submap) {
      // A submap increments the depth search to vm_region_recurse.
      // Use the same address to continue a recursive search within the region.
      depth++;
      continue;
    }

    genMemoryRegion(pid, address, size, info, libraries, results);
    if (exe_only) {
      break;
    }
    address += size;
  }

  if (task != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), task);
  }
}

static std::string getProcPath(int pid) {
  char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
  int bufsize = proc_pidpath(pid, path, sizeof(path));
  if (bufsize <= 0) {
    if (getuid() == 0) {
      QueryData memory_map;
      genProcessMemoryMap(pid, memory_map, true);
      if (memory_map.size() > 0) {
        return memory_map[0]["path"];
      }
    }
    path[0] = '\0';
  }

  return std::string(path);
}

QueryData genProcessMemoryMap(QueryContext& context) {
  QueryData results;

  auto pidlist = getProcList(context);
  for (const auto& pid : pidlist) {
    genProcessMemoryMap(pid, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
