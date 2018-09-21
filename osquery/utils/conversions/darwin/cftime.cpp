/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "cftime.h"

#include <cmath>
#include <boost/lexical_cast.hpp>

namespace osquery {

std::string stringFromCFAbsoluteTime(const CFDataRef& cf_abstime) {
  double value;
  if (CFNumberGetValue((CFNumberRef)cf_abstime, kCFNumberFloat64Type, &value)) {
    // Add seconds difference between CFAbsoluteTime and UNIX times.
    value += kCFAbsoluteTimeIntervalSince1970;

    // Check if overflowed
    if (value > 0) {
      return boost::lexical_cast<std::string>(std::llround(value));
    }
  }

  return "0";
}

}
