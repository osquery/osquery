/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <utility>

#include <boost/noncopyable.hpp>

#define STRIP_FLAG_HELP 1
#include <gflags/gflags.h>

#include <osquery/core/core.h>
#include <osquery/utils/status/status.h>

namespace osquery {

struct FlagDetail {
  std::string description;
  bool shell;
  bool external;
  bool cli;
  bool hidden;
};

struct FlagInfo {
  std::string type;
  std::string description;
  std::string default_value;
  std::string value;
  FlagDetail detail;
};

/**
 * @brief A small tracking wrapper for options, binary flags.
 *
 * The osquery-specific gflags-like options define macro `FLAG` uses a Flag
 * instance to track the options data.
 */
class Flag : private boost::noncopyable {
 public:
  /*
   * @brief Create a new flag.
   *
   * @param name The 'name' or the options switch data.
   * @param flag Flag information filled in using the helper macro.
   *
   * @return A mostly needless flag instance.
   */
  static int create(const std::string& name, const FlagDetail& flag);

  /// Create a Gflags alias to name, using the Flag::getValue accessor.
  static int createAlias(const std::string& alias, const FlagDetail& flag);

  /// Singleton accessor.
  static Flag& instance();

 private:
  /// Keep the ctor private, for accessing through `add` wrapper.
  Flag() = default;
  virtual ~Flag() = default;

 public:
  /// The public flags instance, usable when parsing `--help`.
  static std::map<std::string, FlagInfo> flags();

  /*
   * @brief Access value for a flag name.
   *
   * @param name the flag name.
   * @param value output parameter filled with the flag value on success.
   * @return status of the flag did exist.
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
   * @brief Get the value of an osquery flag.
   *
   * @param name the flag name.
   */
  static std::string getValue(const std::string& name);

  /// Get the flag value as a long int.
  static long int getInt32Value(const std::string& name);

  /*
   * @brief Get the type as a string of an osquery flag.
   *
   * @param name the flag name.
   */
  static std::string getType(const std::string& name);

  /*
   * @brief Get the description as a string of an osquery flag.
   *
   * @param name the flag name.
   */
  static std::string getDescription(const std::string& name);

  /*
   * @brief Checks if the provided flag name corresponds to a CLI only flag
   *
   * @param name the flag name
   */
  static bool isCLIOnlyFlag(const std::string& name);

  /*
   * @brief Print help-style output to stdout for a given flag set.
   *
   * @param shell Only print shell flags.
   * @param external Only print external flags (from extensions).
   */
  static void printFlags(bool shell = false,
                         bool external = false,
                         bool cli = false);

  /**
   * @brief Clear up the custom flags
   * Currently used by the fuzzer targets to prevent
   * the map size to increase indefinitely
   *
   */
  static void resetCustomFlags();

 private:
  /// The container of all shell, CLI, and normal flags.
  std::map<std::string, FlagDetail> flags_;

  /// A container for hidden or aliased (legacy, compatibility) flags.
  std::map<std::string, FlagDetail> aliases_;

  /// Configurations may set "custom_" flags.
  std::map<std::string, std::string> custom_;
};
} // namespace osquery

/*
 * @brief Replace gflags' `DEFINE_type` macros to track osquery flags.
 *
 * Do not use this macro within the codebase directly! Use the subsequent macros
 * that abstract the tail of boolean arguments into meaningful statements.
 *
 * @param type(t) The `_type` symbol portion of the gflags define.
 * @param name(n) The name symbol passed to gflags' `DEFINE_type`.
 * @param value(v) The default value, use a C++ literal.
 * @param desc(d) A string literal used for help display.
 * @param shell(s) Boolean, true if this is only supported in osqueryi.
 * @param extension(e) Boolean, true if this is only supported in an extension.
 * @param cli(c) Boolean, true if this can only be set on the CLI (or flagfile).
 *   This helps documentation since flags can also be set within configuration
 *   as "options".
 * @param hidden(h) Boolean, true if this is hidden from help displays.
 */
#define OSQUERY_FLAG(t, n, v, d, s, e, c, h)                                   \
  DEFINE_##t(n, v, d);                                                         \
  namespace flags {                                                            \
  const int flag_##n = Flag::create(#n, {d, s, e, c, h});                      \
  }

/*
 * @brief Create a command line flag and configuration option.
 *
 * This is an abstraction around Google GFlags that allows osquery to organize
 * the various types of "flags" used to turn features on and off and configure.
 *
 * A FLAG can be set within a `flagfile`, as a command line switch, or via
 * a configuration's "options" key.
 *
 * @param t the type of flag, use the C++ symbol or literal type exactly.
 * @param n the flag name as a symbol, write flagname instead of "flagname".
 * @param v the default value.
 * @param d the help description, please be concise.
 */
#define FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 0, 0)

/// See FLAG, but SHELL_FLAG%s are only available in osqueryi.
#define SHELL_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 1, 0, 0, 0)

/// See FLAG, but EXTENSION_FLAG%s are only available to extensions.
#define EXTENSION_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 1, 0, 0)

/// See FLAG, but CLI_FLAG%s cannot be set within configuration "options".
#define CLI_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 1, 0)

/// See FLAG, but HIDDEN_FLAGS%s are not shown in --help.
#define HIDDEN_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 0, 1)
