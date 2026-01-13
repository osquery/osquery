/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

namespace osquery {

// Placeholder types to replace removed ebpfpub types
struct BPFParameter {
  enum class Type { Integer, Buffer, IntegerPtr, String, Argv };
  enum class Mode { In, Out };
  std::size_t size{};
};

using ParameterList = std::vector<BPFParameter>;
using ParameterListMap = std::unordered_map<std::string, ParameterList>;

extern const ParameterListMap kParameterListMap;

} // namespace osquery
