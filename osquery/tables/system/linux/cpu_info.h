/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

namespace osquery {
namespace tables {

struct CpuInfo {
  std::string device_id;
  std::string model;
  std::string manufacturer;
  std::string processor_type;
  std::string availability;
  std::string cpu_status;
  std::string number_of_cores;
  std::string logical_processors;
  std::string address_width;
  std::string current_clock_speed;
  std::string max_clock_speed;
  std::string socket_designation;
};
/**
 * @brief parse /proc/cpuinfo file into organized struct
 *
 * @param info_file the contents of a /proc/cpuinfo file
 *
 * @return std::vector<CpuInfo> with each element as one physical cpu
 */
std::vector<CpuInfo> parseCpuInfo(const std::string& info_file)

} // namespace tables
} // namespace osquery
