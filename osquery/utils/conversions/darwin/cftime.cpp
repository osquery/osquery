/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
