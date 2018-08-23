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

#include <net/if.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <osquery/core/conversions.h>

namespace osquery {

template <typename T>
T checkTypeAndCast(const std::string& value) {
  auto val = tryTo<T>(value);
  EXPECT_FALSE(val.isError()) << val.getError();
  return val.get();
}

MATCHER_P2(IsBetween,
           a,
           b,
           std::string(negation ? "isn't" : "is") + " between " +
               std::to_string(a) + " and " + std::to_string(b)) {
  return a <= arg && arg <= b;
}

MATCHER(IsBoolean, std::string(negation ? "isn't" : "is") + " a boolean") {
  return arg == 0 || arg == 1;
}

MATCHER(IsNetworkIntfName,
        std::string(negation ? "isn't" : "is") + " a network interface name") {
  return !arg.empty() && arg.length() < IF_NAMESIZE;
}

} // namespace osquery
