// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <boost/make_shared.hpp>

#define STRIP_FLAG_HELP 1
#include <gflags/gflags.h>

#include "osquery/registry.h"

namespace osquery {

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
   * @param name The 'name' or the options switch data.
   * @param value The default value for this flag.
   * @param desc The description printed to the screen during help.
   */
  static Flag& get(const std::string& name = "",
                   const std::string& value = "",
                   const std::string& desc = "") {
    static Flag f;
    if (name != "") {
      f.add(name, value, desc);
    }
    return f;
  }

  /*
   * @brief Wrapper by the Flag::get.
   *
   * @param name The 'name' or the options switch data.
   * @param value The default value for this flag.
   * @param desc The description printed to the screen during help.
   */
  void add(const std::string& name,
           const std::string& value,
           const std::string& desc) {
    flags_.insert(std::make_pair(name, std::make_pair(value, desc)));
  }

 private:
  /// Keep the ctor private, for accessing through `add` wrapper.
  Flag() {}

 public:
  /// The public flags instance, usable when parsing `--help`.
  std::map<std::string, FlagDetail> flags() { return flags_; }

 private:
  /// The private simple map of name to value/desc flag data.
  std::map<std::string, FlagDetail> flags_;
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
    Flag flag = Flag::get(#name, #value, #desc);     \
  }
