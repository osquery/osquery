/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/lexical_cast.hpp>

#include <osquery/core/flags.h>

namespace boost {
/// We define a lexical_cast template for boolean for Gflags boolean string
/// values.
template <>
bool lexical_cast<bool, std::string>(const std::string& arg);

template <>
std::string lexical_cast<std::string, bool>(const bool& arg);
} // namespace boost

namespace osquery {
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

  /*explicit*/ operator T() const {
    return boost::lexical_cast<T>(Flag::getValue(name_));
  }

  FlagAlias(const std::string& /*alias*/,
            const std::string& /*type*/,
            std::string name,
            T* /*storage*/)
      : name_(std::move(name)) {}

 private:
  /// Friendly flag name.
  std::string name_;
};
} // namespace osquery

/**
 * @brief Create an alias to a command line flag.
 *
 * Like OSQUERY_FLAG, do not use this in the osquery codebase. Use the derived
 * macros that abstract the tail of boolean arguments.
 */
#define OSQUERY_FLAG_ALIAS(t, a, n, s, e)                                      \
  FlagAlias<t> FLAGS_##a(#a, #t, #n, &FLAGS_##n);                              \
  namespace flags {                                                            \
  static GFLAGS_NAMESPACE::FlagRegisterer oflag_##a(                           \
      #a, #a, #a, &FLAGS_##n, &FLAGS_##n);                                     \
  const int flag_alias_##a = Flag::createAlias(#a, {#n, s, e, 0, 1});          \
  }

/// See FLAG, FLAG_ALIAS aliases a flag name to an existing FLAG.
#define FLAG_ALIAS(t, a, n) OSQUERY_FLAG_ALIAS(t, a, n, 0, 0)

/// See FLAG_ALIAS, SHELL_FLAG_ALIAS%es are only available in osqueryi.
#define SHELL_FLAG_ALIAS(t, a, n) _OSQUERY_FLAG_ALIAS(t, a, n, 1, 0)

/// See FLAG_ALIAS, EXTENSION_FLAG_ALIAS%es are only available to extensions.
#define EXTENSION_FLAG_ALIAS(a, n) OSQUERY_FLAG_ALIAS(std::string, a, n, 0, 1)
