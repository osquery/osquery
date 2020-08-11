/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "cfnumber.h"

#include <boost/lexical_cast.hpp>

namespace osquery {

std::string stringFromCFNumber(const CFDataRef& cf_number) {
  return stringFromCFNumber(cf_number, CFNumberGetType((CFNumberRef)cf_number));
}

std::string stringFromCFNumber(const CFDataRef& cf_number, CFNumberType type) {
  // Make sure the type is a number.
  if (CFGetTypeID(cf_number) != CFNumberGetTypeID()) {
    return "0";
  }

  // Support a signed 64, a double, and treat everything else as a signed int.
  if (type == kCFNumberSInt64Type) {
    long long int value;
    if (CFNumberGetValue((CFNumberRef)cf_number, type, &value)) {
      return boost::lexical_cast<std::string>(value);
    }
  } else if (type == kCFNumberFloat64Type || type == kCFNumberDoubleType) {
    double value;
    if (CFNumberGetValue((CFNumberRef)cf_number, type, &value)) {
      return boost::lexical_cast<std::string>(value);
    }
  } else if (type == kCFNumberFloat32Type) {
    float value;
    if (CFNumberGetValue((CFNumberRef)cf_number, type, &value)) {
      return boost::lexical_cast<std::string>(value);
    }
  } else {
    unsigned int value;
    if (CFNumberGetValue((CFNumberRef)cf_number, type, &value)) {
      return boost::lexical_cast<std::string>(value);
    }
  }
  // Cast as a string.
  return "0";
}

}
