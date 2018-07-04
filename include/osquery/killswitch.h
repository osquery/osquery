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

#include <boost/core/noncopyable.hpp>
#include <osquery/expected.h>
#include <osquery/status.h>
#include <string>

namespace osquery {

enum class SwitchOnError {
  CallFailed = 1,
  IncorrectResponseFormat = 2,
  IncorrectValue = 3
};

class Killswitch : private boost::noncopyable {
 private:
  Killswitch();

 public:
  ~Killswitch();

  static Killswitch& get() {
    static Killswitch killswitch;
    return killswitch;
  }

  Status refresh();

  Expected<bool, SwitchOnError> isTestSwitchOn();
  Expected<bool, SwitchOnError> isTest2SwitchOn();

 private:
  Expected<bool, SwitchOnError> isSwitchOn(const std::string& key);
};

} // namespace osquery
