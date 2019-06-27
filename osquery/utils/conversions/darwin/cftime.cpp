/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
