/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/flags.h>

namespace osquery {

int Flag::create(const std::string& name, FlagDetail flag) {
  instance().flags_.insert(std::make_pair(name, flag));
  return 0;
}

int Flag::createAlias(const std::string& alias, const std::string& name) {
  instance().aliases_.insert(std::make_pair(alias, name));
  return 0;
}

Status Flag::getDefaultValue(const std::string& name, std::string& value) {
  GFLAGS_NAMESPACE::CommandLineFlagInfo info;
  if (!GFLAGS_NAMESPACE::GetCommandLineFlagInfo(name.c_str(), &info)) {
    return Status(1, "Flags name not found.");
  }

  value = info.default_value;
  return Status(0, "OK");
}

bool Flag::isDefault(const std::string& name) {
  GFLAGS_NAMESPACE::CommandLineFlagInfo info;
  if (!GFLAGS_NAMESPACE::GetCommandLineFlagInfo(name.c_str(), &info)) {
    return false;
  }

  return info.is_default;
}

std::string Flag::getValue(const std::string& name) {
  std::string current_value;
  GFLAGS_NAMESPACE::GetCommandLineOption(name.c_str(), &current_value);
  return current_value;
}

Status Flag::updateValue(const std::string& name, const std::string& value) {
  GFLAGS_NAMESPACE::SetCommandLineOption(name.c_str(), value.c_str());
  return Status(0, "OK");
}

std::map<std::string, FlagInfo> Flag::flags() {
  std::vector<GFLAGS_NAMESPACE::CommandLineFlagInfo> info;
  GFLAGS_NAMESPACE::GetAllFlags(&info);

  std::map<std::string, FlagInfo> flags;
  for (const auto& flag : info) {
    if (instance().flags_.count(flag.name) == 0) {
      // This flag info was not defined within osquery.
      continue;
    }
    flags[flag.name] = {flag.type,
                        flag.description,
                        flag.default_value,
                        flag.current_value,
                        instance().flags_.at(flag.name)};
  }
  return flags;
}

void Flag::printFlags(bool shell, bool external) {
  std::vector<GFLAGS_NAMESPACE::CommandLineFlagInfo> info;
  GFLAGS_NAMESPACE::GetAllFlags(&info);

  size_t max = 0;
  for (const auto& flag : info) {
    max = (max > flag.name.size()) ? max : flag.name.size();
  }
  max += 7;

  auto& details = instance().flags_;
  for (const auto& flag : info) {
    if (details.count(flag.name) == 0) {
      // This flag was not defined within osquery code, skip.
      continue;
    }

    const auto& detail = details.at(flag.name);
    if ((shell && !detail.shell) || (!shell && detail.shell)) {
      continue;
    }

    if ((external && !detail.external) || (!external && detail.external)) {
      continue;
    }

    fprintf(stdout, "    --%s", flag.name.c_str());

    size_t pad = max;
    if (flag.type != "bool") {
      fprintf(stdout, " VALUE");
      pad -= 6;
    }

    fprintf(stdout, "%s", std::string(pad - flag.name.size(), ' ').c_str());
    fprintf(stdout, "%s\n", detail.description.c_str());
  }
}
}
