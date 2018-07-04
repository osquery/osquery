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
<<<<<<< HEAD

#include <string>

#include <osquery/core.h>
#include <osquery/expected.h>
=======
#include <string>

#include <osquery/core.h>
>>>>>>> e33f645c894b057f6380f4b6109b6e81fac00ae9
#include <osquery/plugin.h>
#include <osquery/query.h>

namespace osquery {

enum class SwitchOnError { CallFailed = 1, };

class Killswitch {
 public:
  static Killswitch& get() {
    static Killswitch killswitch;
    return killswitch;
  }

  Status refresh();


  Expected<bool, SwitchOnError> isTestSwitchOn();

 private:
  Expected<bool, SwitchOnError> isSwitchOn(const std::string& key);
};

} // namespace osquery
