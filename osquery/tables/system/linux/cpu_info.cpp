/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <osquery/tables/system/linux/cpu_info.h>

#include <cctype>
#include <string>
#include <vector>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

static constexpr std::string kCpuInfoFile = "/proc/cpuinfo";

struct FileLine {
  std::string_view key;
  std::string_view value;
};

std::vector<FileLine> readLines(const std::string& info_file) {
  std::vector<FileLine> result;
  FileLine current_line;
  // State determines where we currently are in the line:
  // 0: in the key
  // 1: colon
  // 2: in the value
  // 3: new line
  int state = 0;
  int key_start = 0;
  int value_start = 0;
  for (int i = 0; i < info_file.size; ++i) {
    if (info_file[i] == '\n') {
      current_line.value =
          std::string_view(info_file.data() + value_start, i - value_start);
      result.push_back(current_line);
      current_line = {};
      key_start = 0;
      value_start = 0;
      state = 3;
    } else if (info_file[i] == ':') {
      if (state != 0) {
        // This is an error because we should only see a colon in the key.
        // Return empty vector as error.
        return {};
      }
      current_line.key =
          std::string_view(info_file.data() + key_start, i - key_start);
      state = 1; // set state to colon
    } else if (isspace(info_file[i])) {
      // Do nothing, the state stays the same for whitespace.
    } else {
      // Any other character.
      if (state == 1) {
        // Start of value because we were at the colon.
        value_start = i;
      } else if (state == 3) {
        // Start of key because we were at the newline.
        key_start = i;
      }
    }
  }
  return result;
}

std::vector<CpuInfo> parseCpuInfo(const std::string& info_file) {
  std::vector<FileLine> lines = readLines(info_file);
  std::vector<CpuInfo> result;
  CpuInfo current_info = {};
  bool discard_on_reset = false;
  for (int i = 0; i < lines.size(); ++i) {
    FileLine line = lines[i];
    if (line.key.contains("physical id")) {
      for (const CpuInfo& info : result) {
        if (info.device_id == line.value) {
          discard_on_reset = true;
          break;
        }
      }
      current_info.device_id = line.value;
      current_info.socket_designation = line.value;
    } else if (line.key.contains("model name")) {
      current_info.model = line.value;
    } else if (line.key.contains("vendor_id")) {
      current_info.manufacture = line.value;
    } else if (line.key.contains("cpu cores")) {
      current_info.number_of_cores = line.value;
    } else if (line.key.contains("siblings")) {
      current_info.logical_processors = line.value;
    } else if (line.key.contains("address sizes")) {
      // TODO(joesweeney): Address width should be a number, this will need to
      // do more work to get the number.
      current_info.address_width = line.value;
    } else if (line.key.contains("cpu MHz")) {
      current_info.current_clock_speed = line.value;
    } else if (line.key.empty()) {
      if (!discard_on_reset) {
        result.push_back(current_info);
      }
      current_info = {};
      discard_on_reset = false;
    }
  }
  return result;
}

QueryData genCpuInfo(QueryContext& context) {
  Row r;
  QueryData results;

  // TODO(joesweeney): Actually implement the functionality to get this info.
  r["device_id"] = "";
  r["socket_designation"] = "";
  r["model"] = "";
  r["manufacturer"] = "";
  r["processor_type"] = "-1";
  r["availability"] = "-1";
  r["cpu_status"] = "-1";
  r["number_of_cores"] = "-1";
  r["logical_processors"] = "-1";
  r["address_width"] = "-1";
  r["current_clock_speed"] = "-1";
  r["max_clock_speed"] = "-1";
  results.push_back(r);

  return results;
}
} // namespace tables
} // namespace osquery
