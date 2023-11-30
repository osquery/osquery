/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <filesystem>
#include <set>

#include <osquery/core/core.h>

namespace osquery {
struct BlockDevice {
  std::filesystem::path path;
  std::string name;
  std::string parent;
  std::string model;
  std::string serial;
  std::string vendor;
  std::string size;
  std::string block_size;
  std::string uuid;
  std::string type;
  std::string label;

  BlockDevice(const std::string& str_name = "") : name(str_name) {}

  bool operator<(const BlockDevice& rhs) const {
    return name < rhs.name;
  }

  bool operator==(const BlockDevice& rhs) const {
    return name == rhs.name;
  }
};

std::set<BlockDevice> enumerateBlockDevices(std::set<std::string>& context,
                                            const bool include_parents);
} // namespace osquery
