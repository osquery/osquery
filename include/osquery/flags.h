// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#define STRIP_FLAG_HELP 1
#include <gflags/gflags.h>

#include <osquery/registry.h>
#include <osquery/status.h>

#define __GFLAGS_NAMESPACE google

namespace osquery {

/// Value, Description.
typedef std::pair<std::string, std::string> FlagDetail;

/**
 * @brief A small tracking wrapper for options, binary flags.
 *
 * The osquery-specific gflags-like options define macro `DEFINE_osquery_flag`
 * uses a Flag instance to track the options data.
 */
class Flag {
 public:
  /*
   * @brief the instance accessor, but also can register flag data.
   *
   * The accessor is mostly needless. The static instance and registration of
   * flag data requires the accessor wrapper.
   *
   * @param name The 'name' or the options switch data.
   * @param value The default value for this flag.
   * @param desc The description printed to the screen during help.
   * @param shell_only Only print flag help when using `OSQUERY_TOOL_SHELL`.
   *
   * @return A mostly needless flag instance.
   */
  static Flag& get(const std::string& name = "",
                   const std::string& value = "",
                   const std::string& desc = "",
                   bool shell_only = false);

  /*
   * @brief Wrapper by the Flag::get.
   *
   * @param name The 'name' or the options switch data.
   * @param value The default value for this flag.
   * @param desc The description printed to the screen during help.
   * @param shell_only Restrict this flag to the shell help output.
   */
  void add(const std::string& name,
           const std::string& value,
           const std::string& desc,
           bool shell_only);

 private:
  /// Keep the ctor private, for accessing through `add` wrapper.
  Flag() {}

 public:
  /// The public flags instance, usable when parsing `--help`.
  std::map<std::string, FlagDetail> flags() { return flags_; }
  /// The public flags instance, usable when parsing `--help` for the shell.
  std::map<std::string, FlagDetail> shellFlags() { return shell_flags_; }

  /*
   * @brief Access value for a flag name.
   *
   * @param name the flag name.
   * @param value output parameter filled with the flag value on success.
   * @return status of the flag existed.
   */
  static Status getDefaultValue(const std::string& name, std::string& value);

  /*
   * @brief Check if flag value has been overridden.
   *
   * @param name the flag name.
   * @return is the flag set to its default value.
   */
  static bool isDefault(const std::string& name);

  /*
   * @brief Update the flag value by string name,
   *
   * @param name the flag name.
   * @parma value the new value.
   * @return if the value was updated.
   */
  static Status updateValue(const std::string& name, const std::string& value);
  /*
   * @brief Print help-style output to stdout for a given flag set.
   *
   * @param flags A flag set (usually generated from Flag::flags).
   */
  static void printFlags(const std::map<std::string, FlagDetail> flags);

 private:
  /// The private simple map of name to value/desc flag data.
  std::map<std::string, FlagDetail> flags_;
  /// The private simple map of name to value/desc shell-only flag data.
  std::map<std::string, FlagDetail> shell_flags_;
};
}

/*
 * @brief Replace gflags' `DEFINE_type` macros to track osquery flags.
 *
 * @param type The `_type` symbol portion of the gflags define.
 * @param name The name symbol passed to gflags' `DEFINE_type`.
 * @param value The default value, use a C++ literal.
 * @param desc A string literal used for help display.
 */
#define DEFINE_osquery_flag(type, name, value, desc) \
  DEFINE_##type(name, value, desc);                  \
  namespace flag_##name {                            \
    Flag flag = Flag::get(#name, #value, desc);      \
  }

/*
 * @brief A duplicate of DEFINE_osquery_flag except the help output will only
 * show when using OSQUERY_TOOL_SHELL (osqueryi).
 *
 * @param type The `_type` symbol portion of the gflags define.
 * @param name The name symbol passed to gflags' `DEFINE_type`.
 * @param value The default value, use a C++ literal.
 * @param desc A string literal used for help display.
 */
#define DEFINE_shell_flag(type, name, value, desc)    \
  DEFINE_##type(name, value, desc);                   \
  namespace flag_##name {                             \
    Flag flag = Flag::get(#name, #value, desc, true); \
  }
