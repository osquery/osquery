/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

std::string getIOKitProperty(const CFMutableDictionaryRef& details,
                             const std::string& key);
}
}
