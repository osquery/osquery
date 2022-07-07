/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_map>

#include <gtest/gtest.h>

#include <osquery/utils/conversions/darwin/cfdictionary.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

namespace osquery {

class ConversionsTests : public testing::Test {};

TEST_F(ConversionsTests, getPropertiesFromDictionary) {
  CFMutableDictionaryRef dict;
  dict = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                   0,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(dict, CFSTR("string"), CFSTR("string_value"));

  int number = 1234;
  CFNumberRef n =
      CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &number);
  CFDictionaryAddValue(dict, CFSTR("number"), n);

  CFDictionaryAddValue(dict, CFSTR("boolean_true"), kCFBooleanTrue);
  CFDictionaryAddValue(dict, CFSTR("boolean_false"), kCFBooleanFalse);

  auto string_value = getPropertiesFromDictionary(dict, "string");
  EXPECT_EQ(string_value, "string_value");

  auto number_value = getPropertiesFromDictionary(dict, "number");
  EXPECT_EQ(number_value, "1234");

  auto boolean_true = getPropertiesFromDictionary(dict, "boolean_true");
  EXPECT_EQ(boolean_true, "1");

  auto boolean_false = getPropertiesFromDictionary(dict, "boolean_false");
  EXPECT_EQ(boolean_false, "0");

  if (n != nullptr) {
    CFRelease(n);
  }

  if (dict != nullptr) {
    CFRelease(dict);
  }
}
} // namespace osquery
