/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <map>

#include <boost/algorithm/string/join.hpp>

#include <sys/stat.h>

#include <osquery/filesystem/fileops.h>

namespace osquery {
namespace {
/// The list of supported flags, as documented in `man 2 chflags`
/// And in https://github.com/apple/darwin-xnu/blob/master/bsd/sys/stat.h
const std::map<std::uint32_t, std::string> kBsdFlagMap = {
    {UF_APPEND, "UF_APPEND"}, // 0x00000004
    {UF_COMPRESSED, "COMPRESSED"}, // 0x00000020
    {UF_DATAVAULT, "DATAVAULT"}, // 0x00000080
    {UF_HIDDEN, "HIDDEN"}, // 0x00008000
    {UF_IMMUTABLE, "UF_IMMUTABLE"}, // 0x00000002
    {UF_NODUMP, "NODUMP"}, // 0x00000001
    {UF_OPAQUE, "OPAQUE"}, // 0x00000008
    {UF_TRACKED, "TRACKED"}, // 0x00000040

    {SF_APPEND, "SF_APPEND"}, // 0x00040000
    {SF_ARCHIVED, "ARCHIVED"}, // 0x00010000
    {SF_IMMUTABLE, "SF_IMMUTABLE"}, // 0x00020000
    {SF_NOUNLINK, "SF_NOUNLINK"}, // 0x00100000
    {SF_RESTRICTED, "SF_RESTRICTED"}, // 0x00080000
    {SF_SUPPORTED, "SF_SUPPORTED"}, // 0x001f0000
};

std::uint32_t getBsdFlagMask() {
  std::uint32_t result = 0U;

  for (const auto& p : kBsdFlagMap) {
    const auto& bit = p.first;
    result |= bit;
  }

  return result;
}
} // namespace

Status describeBSDFileFlags(std::string& output, std::uint32_t st_flags) {
  output.clear();

  static const auto flag_mask = getBsdFlagMask();

  std::vector<std::string> label_list;

  for (const auto& p : kBsdFlagMap) {
    const auto& bit = p.first;
    const auto& label = p.second;

    if ((st_flags & bit) != 0U) {
      label_list.push_back(label);
    }
  }

  // Get the bits that are not documented and show them as a hex number
  auto undocumented_flags = st_flags & (~flag_mask);
  if (undocumented_flags != 0U) {
    std::stringstream buffer;
    buffer << "0x" << std::setw(8) << std::setfill('0') << std::hex
           << undocumented_flags;

    label_list.push_back(buffer.str());
  }

  output = boost::algorithm::join(label_list, ", ");

  if (undocumented_flags != 0U) {
    return Status::failure("undocumented flags present");
  }

  return Status::success();
}
} // namespace osquery
