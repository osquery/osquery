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
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

static const std::string kCpuInfoFile = "/proc/cpuinfo";

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
  for (int i = 0; i < info_file.size(); ++i) {
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
        VLOG(0) << "Saw colon in state: " << state << ". At offset :" << i;
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
        state = 2; // In value now.
      } else if (state == 3) {
        // Start of key because we were at the newline.
        key_start = i;
        state = 0; // In key now.
      }
    }
  }
  return result;
}

bool hasFlag(const std::string_view& flags,
             const std::string_view& potential_flag) {
  std::vector<std::string_view> all_flags;
  int start = 0;
  int end = 0;
  do {
    if (flags[end] == ' ' || end == flags.size()) {
      all_flags.push_back(std::string_view(flags.data() + start, end - start));
      start = end + 1;
    }
    end += 1;
  } while (end <= flags.size());
  for (const auto& str : all_flags) {
    if (str == potential_flag) {
      return true;
    }
  }
  return false;
}

bool strStartsWith(const std::string_view& string,
                   const std::string_view& potential_substring) {
  auto pos = string.find(potential_substring);
  if (pos == string.npos || pos != 0) {
    return false;
  }
  return true;
}

std::vector<CpuInfo> parseCpuInfo(const std::string& info_file) {
  std::vector<FileLine> lines = readLines(info_file);
  std::vector<CpuInfo> result;
  CpuInfo current_info = {};
  bool discard_on_reset = false;
  for (int i = 0; i < lines.size(); ++i) {
    FileLine line = lines[i];
    if (strStartsWith(line.key, "physical id")) {
      for (const CpuInfo& info : result) {
        if (info.device_id == line.value) {
          discard_on_reset = true;
          break;
        }
      }
      current_info.device_id = line.value;
      current_info.socket_designation = line.value;
    } else if (strStartsWith(line.key, "model name")) {
      current_info.model = line.value;
    } else if (strStartsWith(line.key, "vendor_id")) {
      current_info.manufacturer = line.value;
    } else if (strStartsWith(line.key, "cpu cores")) {
      current_info.number_of_cores = line.value;
    } else if (strStartsWith(line.key, "siblings")) {
      current_info.logical_processors = line.value;
    } else if (strStartsWith(line.key, "flags")) {
      // Address width on Windows indicates whether the CPU is 32 bits or 64
      // bits. In /proc/cpuinfo the flags field will contain the "lm" flag (long
      // mode) if it is 64 bit, otherwise it will be 32 bit. So we check for
      // that flag.
      std::string width = "32";
      if (hasFlag(line.value, "lm")) {
        width = "64";
      }
      current_info.address_width = width;
    } else if (strStartsWith(line.key, "cpu MHz")) {
      current_info.current_clock_speed = line.value;
    } else if (line.key.empty()) {
      if (!discard_on_reset) {
        if (!current_info.device_id.empty()) {
          result.push_back(current_info);
        }
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
  std::string info_file;
  Status status = readFile(kCpuInfoFile, info_file);
  if (!status.ok()) {
    return results;
  }
  std::vector<CpuInfo> cpu_infos = parseCpuInfo(info_file);
  for (const CpuInfo& info : cpu_infos) {
    r["device_id"] = info.device_id;
    r["socket_designation"] = info.socket_designation;
    r["model"] = info.model;
    r["manufacturer"] = info.manufacturer;
    r["processor_type"] = info.processor_type;
    r["availability"] = info.availability;
    r["cpu_status"] = info.cpu_status;
    r["number_of_cores"] = info.number_of_cores;
    r["logical_processors"] = info.logical_processors;
    r["address_width"] = info.address_width;
    r["current_clock_speed"] = info.current_clock_speed;
    r["max_clock_speed"] = info.max_clock_speed;
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
