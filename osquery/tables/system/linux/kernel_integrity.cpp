// Copyright 2004-present Facebook. All Rights Reserved.

#include <fstream>

#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#define DECLARE_TABLE_IMPLEMENTATION_kernel_integrity
#include <generated/tables/tbl_kernel_integrity_defs.hpp>

namespace osquery {
namespace tables {

const std::string kKernelSyscallAddrModifiedPath = "/sys/kernel/camb/syscall_addr_modified";
const std::string kKernelTextHashPath = "/sys/kernel/camb/text_segment_hash";

QueryData genKernelIntegrity(QueryContext &context) {
  QueryData results;
  Row r;
  std::string content;
  std::string text_segment_hash;
  std::string syscall_addr_modified;

  // Get an integral value, 0 or 1, for whether a syscall table pointer is modified.
  auto f1 = osquery::readFile(kKernelSyscallAddrModifiedPath, content);
  if (f1.ok()) {
    boost::trim(content);
    syscall_addr_modified = content;
  } else {
    VLOG(1) << "Cannot read file: " << kKernelSyscallAddrModifiedPath;
    return results;
  }

  // Get the hash value for the kernel's .text memory segment
  auto f2 = osquery::readFile(kKernelTextHashPath, content);
  if (f2.ok()) {
    boost::trim(content);
    text_segment_hash = content;
  } else {
    VLOG(1) << "Cannot read file: " << kKernelTextHashPath;
    return results;
  }

  r["sycall_addr_modified"] = syscall_addr_modified;
  r["text_segment_hash"] = text_segment_hash;
  results.push_back(r);

  return results;
}
}
}
