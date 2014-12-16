// Copyright 2004-present Facebook. All Rights Reserved.

#include <osquery/flags.h>

namespace osquery {

Flag& Flag::get(const std::string& name,
                const std::string& type,
                const std::string& value,
                const std::string& desc,
                bool shell_only) {
  static Flag f;
  if (name != "") {
    f.add(name, type, value, desc, shell_only);
  }
  return f;
}

void Flag::add(const std::string& name,
               const std::string& type,
               const std::string& value,
               const std::string& desc,
               bool shell_only) {
  auto escaped_value = value;
  if (type == "string") {
    escaped_value.erase(0, 1);
    escaped_value.erase(escaped_value.end() - 1, escaped_value.end());
  }
  if (!shell_only) {
    flags_.insert(
        std::make_pair(name, std::make_tuple(type, escaped_value, desc)));
  } else {
    shell_flags_.insert(
        std::make_pair(name, std::make_tuple(type, escaped_value, desc)));
  }
}

Status Flag::getDefaultValue(const std::string& name, std::string& value) {
  if (Flag::get().flags().count(name)) {
    value = std::get<1>(Flag::get().flags()[name]);
  } else if (Flag::get().shellFlags().count(name)) {
    value = std::get<1>(Flag::get().shellFlags()[name]);
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

std::string Flag::getValue(const std::string& name) {
  std::string current_value;
  __GFLAGS_NAMESPACE::GetCommandLineOption(name.c_str(), &current_value);
  return current_value;
}

Status Flag::updateValue(const std::string& name, const std::string& value) {
  __GFLAGS_NAMESPACE::SetCommandLineOption(name.c_str(), value.c_str());
  return Status(0, "OK");
}

void Flag::printFlags(const std::map<std::string, FlagDetail> flags) {
  for (const auto& flag : flags) {
    fprintf(stdout,
            "  --%s=%s\n    %s\n",
            flag.first.c_str(),
            std::get<1>(flag.second).c_str(),
            std::get<2>(flag.second).c_str());
  }
}
}
