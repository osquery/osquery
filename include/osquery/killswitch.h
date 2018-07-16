/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once
#include <string>

#include <boost/core/noncopyable.hpp>

#include <osquery/expected.h>
#include <osquery/status.h>

namespace osquery {

class Killswitch : private boost::noncopyable {
 private:
  Killswitch();

 public:
  virtual ~Killswitch();

  /*
  // Author: @guliashvili
  // Creation Time: 11 / 07 / 2018
  bool isMyTutorialFeatureEnabled();
  */

  static Killswitch& get() {
    static Killswitch killswitch;
    return killswitch;
  }

  Status refresh();

 private:
  bool isNewCodeEnabled(const std::string& key);

  enum class IsEnabledError {
    CallFailed = 1,
    IncorrectResponseFormat = 2,
    IncorrectValue = 3
  };
  Expected<bool, Killswitch::IsEnabledError> isEnabled(const std::string& key);

  FRIEND_TEST(KillswitchJSONTests, test_killswitch_JSON_plugin_initial_values);
  FRIEND_TEST(KillswitchJSONTests, test_killswitch_JSON_plugin_switch_valid);
  FRIEND_TEST(KillswitchTests, test_killswitch_plugin);
};

} // namespace osquery
