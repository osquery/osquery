/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flagalias.h>
#include <osquery/core/flags.h>
#include <osquery/registry/registry.h>
#include <osquery/utils/conversions/tryto.h>

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
} // namespace boost

namespace flags = GFLAGS_NAMESPACE;

namespace osquery {

Flag& Flag::instance() {
  static Flag f;
  return f;
}

int Flag::create(const std::string& name, const FlagDetail& flag) {
  instance().flags_.insert(std::make_pair(name, flag));
  return 0;
}

int Flag::createAlias(const std::string& alias, const FlagDetail& flag) {
  instance().aliases_.insert(std::make_pair(alias, flag));
  return 0;
}

Status Flag::getDefaultValue(const std::string& name, std::string& value) {
  flags::CommandLineFlagInfo info;
  if (!flags::GetCommandLineFlagInfo(name.c_str(), &info)) {
    return Status(1, "Flags name not found.");
  }

  value = info.default_value;
  return Status::success();
}

bool Flag::isDefault(const std::string& name) {
  flags::CommandLineFlagInfo info;
  if (!flags::GetCommandLineFlagInfo(name.c_str(), &info)) {
    return false;
  }

  return info.is_default;
}

std::string Flag::getValue(const std::string& name) {
  const auto& custom = instance().custom_;
  auto custom_flag = custom.find(name);
  if (custom_flag != custom.end()) {
    return custom_flag->second;
  }

  std::string current_value;
  auto found = flags::GetCommandLineOption(name.c_str(), &current_value);

  // If this is an extension and the flag was not found, forward the request.
  if (Registry::get().external() && !found) {
    PluginResponse resp;
    Registry::call("config", {{"name", name}, {"action", "option"}}, resp);
    if (resp.size() != 0) {
      auto value = resp[0].find("value");
      if (value != resp[0].end()) {
        return value->second;
      }
    }
  }

  return current_value;
}

long int Flag::getInt32Value(const std::string& name) {
  return tryTo<long int>(Flag::getValue(name), 10).takeOr(0l);
}

std::string Flag::getType(const std::string& name) {
  flags::CommandLineFlagInfo info;
  if (!flags::GetCommandLineFlagInfo(name.c_str(), &info)) {
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

bool Flag::isCLIOnlyFlag(const std::string& name) {
  const auto& flags = instance().flags_;
  const auto it = instance().flags_.find(name);

  if (it == flags.end()) {
    return false;
  }

  return it->second.cli;
}

Status Flag::updateValue(const std::string& name, const std::string& value) {
  if (instance().flags_.count(name) > 0) {
    flags::SetCommandLineOption(name.c_str(), value.c_str());
    return Status::success();
  } else if (instance().aliases_.count(name) > 0) {
    // Updating a flag by an alias name.
    auto& real_name = instance().aliases_.at(name).description;
    flags::SetCommandLineOption(real_name.c_str(), value.c_str());
    return Status::success();
  } else if (name.find("custom_") == 0) {
    instance().custom_[name] = value;
  }
  return Status(1, "Flag not found");
}

std::map<std::string, FlagInfo> Flag::flags() {
  std::vector<flags::CommandLineFlagInfo> info;
  flags::GetAllFlags(&info);

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
  for (const auto& flag : instance().custom_) {
    flags[flag.first] = {"string", "", "", flag.second, {}};
  }
  return flags;
}

void Flag::printFlags(bool shell, bool external, bool cli) {
  std::vector<flags::CommandLineFlagInfo> info;
  flags::GetAllFlags(&info);
  auto& details = instance().flags_;

  std::map<std::string, const flags::CommandLineFlagInfo*> ordered_info;
  for (const auto& flag : info) {
    ordered_info[flag.name] = &flag;
  }

  // Determine max indent needed for all flag names.
  size_t max = 0;
  for (const auto& flag : details) {
    max = (max > flag.first.size()) ? max : flag.first.size();
  }
  // Additional index for flag values.
  max += 6;

  // Show the Gflags-specific 'flagfile'.
  if (!shell && cli) {
    fprintf(stdout, "    --flagfile PATH");
    fprintf(stdout, "%s", std::string(max - 8 - 5, ' ').c_str());
    fprintf(stdout, "  Line-delimited file of additional flags\n");
  }

  auto& aliases = instance().aliases_;
  for (const auto& flag : ordered_info) {
    if (details.count(flag.second->name) > 0) {
      const auto& detail = details.at(flag.second->name);
      if ((shell && !detail.shell) || (!shell && detail.shell) ||
          (external && !detail.external) || (!external && detail.external) ||
          (cli && !detail.cli) || (!cli && detail.cli) || detail.hidden) {
        continue;
      }
    } else if (aliases.count(flag.second->name) > 0) {
      const auto& alias = aliases.at(flag.second->name);
      // Aliases are only printed if this is an external tool and the alias
      // is external.
      if (!alias.external || !external) {
        continue;
      }
    } else {
      // This flag was not defined as an osquery flag or flag alias.
      continue;
    }

    fprintf(stdout, "    --%s", flag.second->name.c_str());

    int pad = static_cast<int>(max);
    if (flag.second->type != "bool") {
      fprintf(stdout, " VALUE");
      pad -= 6;
    }
    pad -= static_cast<int>(flag.second->name.size());

    if (pad > 0 && pad < 80) {
      // Never pad more than 80 characters.
      fprintf(stdout, "%s", std::string(pad, ' ').c_str());
    }
    fprintf(stdout, "  %s\n", getDescription(flag.second->name).c_str());
  }
}

void Flag::resetCustomFlags() {
  instance().custom_.clear();
}
} // namespace osquery
