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

namespace boost {
template <>
bool lexical_cast<bool, std::string>(const std::string& arg) {
  std::istringstream ss(arg);
  bool b;
  ss >> std::boolalpha >> b;
  return b;
}

template <>
std::string lexical_cast<std::string, bool>(const bool& b) {
  std::ostringstream ss;
  ss << std::boolalpha << b;
  return ss.str();
}
}

namespace osquery {

int Flag::create(const std::string& name, const FlagDetail& flag) {
  instance().flags_.insert(std::make_pair(name, flag));
  return 0;
}

int Flag::createAlias(const std::string& alias, const FlagDetail& flag) {
  instance().aliases_.insert(std::make_pair(alias, flag));
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

std::string Flag::getType(const std::string& name) {
  GFLAGS_NAMESPACE::CommandLineFlagInfo info;
  if (!GFLAGS_NAMESPACE::GetCommandLineFlagInfo(name.c_str(), &info)) {
    return "";
  }
  return info.type;
}

std::string Flag::getDescription(const std::string& name) {
  if (instance().flags_.count(name)) {
    return instance().flags_.at(name).description;
  }

  if (instance().aliases_.count(name)) {
    return getDescription(instance().aliases_.at(name).description);
  }
  return "";
}

Status Flag::updateValue(const std::string& name, const std::string& value) {
  if (instance().flags_.count(name) > 0) {
    GFLAGS_NAMESPACE::SetCommandLineOption(name.c_str(), value.c_str());
    return Status(0, "OK");
  } else if (instance().aliases_.count(name) > 0) {
    // Updating a flag by an alias name.
    auto& real_name = instance().aliases_.at(name).description;
    GFLAGS_NAMESPACE::SetCommandLineOption(real_name.c_str(), value.c_str());
    return Status(0, "OK");
  }
  return Status(1, "Flag not found");
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

    // Set the flag info from the internal info kept by Gflags, except for
    // the stored description. Gflag keeps an "unknown" value if the flag
    // was declared without a definition.
    flags[flag.name] = {flag.type,
                        instance().flags_.at(flag.name).description,
                        flag.default_value,
                        flag.current_value,
                        instance().flags_.at(flag.name)};
  }
  return flags;
}

void Flag::printFlags(bool shell, bool external, bool cli) {
  std::vector<GFLAGS_NAMESPACE::CommandLineFlagInfo> info;
  GFLAGS_NAMESPACE::GetAllFlags(&info);
  auto& details = instance().flags_;

  // Determine max indent needed for all flag names.
  size_t max = 0;
  for (const auto& flag : details) {
    max = (max > flag.first.size()) ? max : flag.first.size();
  }
  // Additional index for flag values.
  max += 6;

  auto& aliases = instance().aliases_;
  for (const auto& flag : info) {
    if (details.count(flag.name) > 0) {
      const auto& detail = details.at(flag.name);
      if ((shell && !detail.shell) || (!shell && detail.shell) ||
          (external && !detail.external) || (!external && detail.external) ||
          (cli && !detail.cli) || (!cli && detail.cli)) {
        continue;
      }
    } else if (aliases.count(flag.name) > 0) {
      const auto& alias = aliases.at(flag.name);
      // Aliases are only printed if this is an external tool and the alias
      // is external.
      if (!alias.external || !external) {
        continue;
      }
    } else {
      // This flag was not defined as an osquery flag or flag alias.
      continue;
    }

    fprintf(stdout, "    --%s", flag.name.c_str());

    int pad = max;
    if (flag.type != "bool") {
      fprintf(stdout, " VALUE");
      pad -= 6;
    }
    pad -= flag.name.size();

    if (pad > 0 && pad < 80) {
      // Never pad more than 80 characters.
      fprintf(stdout, "%s", std::string(pad, ' ').c_str());
    }
    fprintf(stdout, "  %s\n", getDescription(flag.name).c_str());
  }
}
}
