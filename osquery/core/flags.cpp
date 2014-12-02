// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/flags.h"

namespace osquery {

Flag& Flag::get(const std::string& name,
                const std::string& value,
                const std::string& desc,
                bool shell_only) {
  static Flag f;
  if (name != "") {
    f.add(name, value, desc, shell_only);
  }
  return f;
}

void Flag::add(const std::string& name,
               const std::string& value,
               const std::string& desc,
               bool shell_only) {
  if (!shell_only) {
    flags_.insert(std::make_pair(name, std::make_pair(value, desc)));
  } else {
    shell_flags_.insert(std::make_pair(name, std::make_pair(value, desc)));
  }
}

Status Flag::getDefaultValue(const std::string& name, std::string& value) {
  if (Flag::get().flags().count(name)) {
    value = Flag::get().flags()[name].first;
  } else if (Flag::get().shellFlags().count(name)) {
    value = Flag::get().shellFlags()[name].first;
  } else {
    return Status(1, "Flag name not found.");
  }
  return Status(0, "OK");
}

bool Flag::isDefault(const std::string& name) {
  std::string current_value;
  if (!__GFLAGS_NAMESPACE::GetCommandLineOption(name.c_str(), &current_value)) {
    return false;
  }

  std::string default_value;
  if (!getDefaultValue(name, default_value).ok()) {
    return false;
  }

  return (default_value == current_value);
}

Status Flag::updateValue(const std::string& name, const std::string& value) {
  __GFLAGS_NAMESPACE::SetCommandLineOption(name.c_str(), value.c_str());
  return Status(0, "OK");
}

void Flag::printFlags(const std::map<std::string, FlagDetail> flags) {
  for (const auto& flag : flags) {
    fprintf(stdout,
            "  --%s, --%s=%s\n    %s\n",
            flag.first.c_str(),
            flag.first.c_str(),
            flag.second.first.c_str(),
            flag.second.second.c_str());
  }
}
}
