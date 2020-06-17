/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <iomanip>
#include <map>

#include <boost/algorithm/string/join.hpp>

#include <sys/stat.h>

#include <osquery/filesystem/fileops.h>

namespace osquery {
namespace {
/// The list of supported flags, as documented in `man 2 chflags`
const std::map<std::uint32_t, std::string> kBsdFlagMap = {
    {UF_NODUMP, "NODUMP"},
    {UF_IMMUTABLE, "UF_IMMUTABLE"},
    {UF_APPEND, "UF_APPEND"},
    {UF_OPAQUE, "OPAQUE"},
    {UF_HIDDEN, "HIDDEN"},
    {SF_ARCHIVED, "ARCHIVED"},
    {SF_IMMUTABLE, "SF_IMMUTABLE"},
    {SF_APPEND, "SF_APPEND"}};

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
