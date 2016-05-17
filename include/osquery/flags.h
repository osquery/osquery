/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>

#include <boost/lexical_cast.hpp>

#define STRIP_FLAG_HELP 1
#include <gflags/gflags.h>

#include <osquery/core.h>

#ifdef FREEBSD
#define GFLAGS_NAMESPACE gflags
#elif !defined(GFLAGS_NAMESPACE)
#define GFLAGS_NAMESPACE google
#endif

namespace boost {
/// We define a lexical_cast template for boolean for Gflags boolean string
/// values.
template <>
bool lexical_cast<bool, std::string>(const std::string& arg);

template <>
std::string lexical_cast<std::string, bool>(const bool& b);
}

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
class Flag {
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

  static Flag& instance() {
    static Flag f;
    return f;
  }

 private:
  /// Keep the ctor private, for accessing through `add` wrapper.
  Flag() {}
  virtual ~Flag() {}

  Flag(Flag const&);
  void operator=(Flag const&);

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
   * @brief Print help-style output to stdout for a given flag set.
   *
   * @param shell Only print shell flags.
   * @param external Only print external flags (from extensions).
   */
  static void printFlags(bool shell = false,
                         bool external = false,
                         bool cli = false);

 private:
  std::map<std::string, FlagDetail> flags_;
  std::map<std::string, FlagDetail> aliases_;
};

/**
 * @brief Helper accessor/assignment alias class to support deprecated flags.
 *
 * This templated class wraps Flag::updateValue and Flag::getValue to 'alias'
 * a deprecated flag name as the updated name. The helper macro FLAG_ALIAS
 * will create a global variable instances of this wrapper using the same
 * Gflags naming scheme to prevent collisions and support existing callsites.
 */
template <typename T>
class FlagAlias {
 public:
  FlagAlias& operator=(T const& v) {
    Flag::updateValue(name_, boost::lexical_cast<std::string>(v));
    return *this;
  }

  operator T() const { return boost::lexical_cast<T>(Flag::getValue(name_)); }

  FlagAlias(const std::string& alias,
            const std::string& type,
            const std::string& name,
            T* storage)
      : name_(name) {}

 private:
  std::string name_;
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
#define OSQUERY_FLAG(t, n, v, d, s, e, c, h)              \
  DEFINE_##t(n, v, d);                                    \
  namespace flags {                                       \
  const int flag_##n = Flag::create(#n, {d, s, e, c, h}); \
  }

#define FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 0, 0)
#define SHELL_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 1, 0, 0, 0)
#define EXTENSION_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 1, 0, 0)
#define CLI_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 1, 0)
#define HIDDEN_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 0, 1)

#define OSQUERY_FLAG_ALIAS(t, a, n, s, e)                             \
  FlagAlias<t> FLAGS_##a(#a, #t, #n, &FLAGS_##n);                     \
  namespace flags {                                                   \
  static GFLAGS_NAMESPACE::FlagRegisterer oflag_##a(                  \
      #a, #t, #a, #a, &FLAGS_##n, &FLAGS_##n);                        \
  const int flag_alias_##a = Flag::createAlias(#a, {#n, s, e, 0, 1}); \
  }

#define FLAG_ALIAS(t, a, n) OSQUERY_FLAG_ALIAS(t, a, n, 0, 0)
#define SHELL_FLAG_ALIAS(t, a, n) _OSQUERY_FLAG_ALIAS(t, a, n, 1, 0)
#define EXTENSION_FLAG_ALIAS(a, n) OSQUERY_FLAG_ALIAS(std::string, a, n, 0, 1)
