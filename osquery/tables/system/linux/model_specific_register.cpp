/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#define MSR_FILENAME_BUFFER_SIZE 32

#define NO_MASK 0xFFFFFFFFFFFFFFFFULL

// Defines taken from uapi/asm/msr-index.h from the linux kernel.
#define MSR_PLATFORM_INFO 0x000000ce

#define MSR_IA32_FEATURE_CONTROL 0x0000003a

#define MSR_IA32_PERF_STATUS 0x00000198
#define MSR_IA32_PERF_CTL 0x00000199
#define INTEL_PERF_CTL_MASK 0xffff

#define MSR_IA32_MISC_ENABLE 0x000001a0

#define MSR_TURBO_RATIO_LIMIT 0x000001ad

#define MSR_IA32_MISC_ENABLE_TURBO_DISABLE_BIT 38
#define MSR_IA32_MISC_ENABLE_TURBO_DISABLE \
  (1ULL << MSR_IA32_MISC_ENABLE_TURBO_DISABLE_BIT)

// Run Time Average Power Limiting (RAPL).
#define MSR_RAPL_POWER_UNIT 0x00000606
#define MSR_PKG_ENERGY_STATUS 0x00000611
#define MSR_PKG_POWER_LIMIT 0x00000610

namespace osquery {
namespace tables {

// These are the entries to retrieve from the model specific register
struct msr_record_t {
  const char *name;
  const off_t offset;
  const uint64_t mask;
  const int is_flag;
};
const static msr_record_t fields[] = {
    {.name = "turbo_disabled",
     .offset = MSR_IA32_MISC_ENABLE,
     .mask = MSR_IA32_MISC_ENABLE_TURBO_DISABLE,
     .is_flag = true},
    {.name = "turbo_ratio_limit",
     .offset = MSR_TURBO_RATIO_LIMIT,
     .mask = NO_MASK,
     .is_flag = false},
    {.name = "platform_info",
     .offset = MSR_PLATFORM_INFO,
     .mask = NO_MASK,
     .is_flag = false},
    {.name = "perf_status",
     .offset = MSR_IA32_PERF_STATUS,
     .mask = NO_MASK,
     .is_flag = false},
    {.name = "perf_ctl",
     .offset = MSR_IA32_PERF_CTL,
     .mask = INTEL_PERF_CTL_MASK,
     .is_flag = false},
    {.name = "feature_control",
     .offset = MSR_IA32_FEATURE_CONTROL,
     .mask = NO_MASK,
     .is_flag = false},
    {.name = "rapl_power_limit",
     .offset = MSR_PKG_POWER_LIMIT,
     .mask = NO_MASK,
     .is_flag = false},
    {.name = "rapl_energy_status",
     .offset = MSR_PKG_ENERGY_STATUS,
     .mask = NO_MASK,
     .is_flag = false},
    {.name = "rapl_power_units",
     .offset = MSR_RAPL_POWER_UNIT,
     .mask = NO_MASK,
     .is_flag = false}};

void getModelSpecificRegisterData(QueryData &results, int cpu_number) {
  auto msr_filename =
    std::string("/dev/cpu/") + std::to_string(cpu_number) + "/msr";

  int fd = open(msr_filename.c_str(), O_RDONLY);
  if (fd < 0) {
    int err = errno;
    TLOG << "Could not open msr file " << msr_filename
         << " check the msr kernel module is enabled.";
    if (err == EACCES) {
      TLOG << "Could not access msr device.  Run osquery as root.";
    }
    return;
  }

  Row r;
  r["processor_number"] = BIGINT(cpu_number);
  for (const msr_record_t &field : fields) {
    uint64_t output;
    ssize_t size = pread(fd, &output, sizeof(uint64_t), field.offset);
    if (size != sizeof(uint64_t)) {
      // Processor does not have a record of this type.
      continue;
    }
    if (field.is_flag) {
      r[field.name] = BIGINT((output & field.mask) ? 1 : 0);
    } else {
      r[field.name] = BIGINT(output & field.mask);
    }
  }
  results.push_back(r);
  close(fd);

  return;
}

// Filter only for filenames starting with a digit.
int msrScandirFilter(const struct dirent *entry) {
  if (isdigit(entry->d_name[0])) {
    return 1;
  } else {
    return 0;
  }
}

QueryData genModelSpecificRegister(QueryContext &context) {
  QueryData results;

  struct dirent **entries = nullptr;
  int num_entries = scandir("/dev/cpu", &entries, msrScandirFilter, 0);
  if (num_entries < 1) {
    TLOG << "No msr information check msr kernel module is enabled.";
    return results;
  }
  while (num_entries--) {
    getModelSpecificRegisterData(results, atoi(entries[num_entries]->d_name));
    free(entries[num_entries]);
  }
  free(entries);

  return results;
}
}
}
