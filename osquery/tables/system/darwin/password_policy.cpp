/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <OpenDirectory/OpenDirectory.h>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfdictionary.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

QueryData genPasswordPolicy(QueryContext& context) {
  QueryData results;

  CFErrorRef error = nullptr;
  // Create a node of type LocalNodes with the default OpenDirectory Session
  auto node = ODNodeCreateWithNodeType(
      kCFAllocatorDefault, kODSessionDefault, kODNodeTypeLocalNodes, &error);
  if (node == nullptr) {
    VLOG(1) << "password_policy: Error creating an OpenDirectory node";
    return {};
  }

  /*
   * policies is a dictionary with `policyCategoryPasswordContent` as an
   * optional key. The value  of `policyCategoryPasswordContent` is an array of
   * policy dictionaries that specify the required content of passwords.
   * Each element of that array, is a dictionary with following keys:
   * `policyContent`, `policyContentDescription`, and `policyContentDescription`
   *
   * (From Apple's docs)
   *
   * Note: `ODNodeCopyAccountPolicies` is the only viable API now, which gets
   * any policies configured for the node.
   * Similar API in OpenDirectory has been deprecated.
   */
  auto policies = ODNodeCopyAccountPolicies(node, &error);
  if (policies == nullptr) {
    VLOG(1) << "password_policy: Error getting account policies";
    return {};
  }

  auto count = CFDictionaryGetCount(policies);
  if (count == 0) {
    VLOG(1) << "password_policy: Empty account policies for the node";
    CFRelease(policies);
    return {};
  }

  if (!CFDictionaryContainsKey(policies,
                               CFSTR("policyCategoryPasswordContent"))) {
    VLOG(1)
        << "password_policy: Account policy does not contain password content";
    CFRelease(policies);
    return {};
  }

  auto content =
      CFDictionaryGetValue(policies, CFSTR("policyCategoryPasswordContent"));
  if (content == nullptr) {
    return {};
  }

  count = CFArrayGetCount((CFArrayRef)content);
  for (CFIndex i = 0; i < count; i++) {
    Row r;
    r["policy_content"] = getPropertiesFromDictionary(
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)content, i),
        "policyContent");

    auto identifier = getPropertiesFromDictionary(
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)content, i),
        "policyIdentifier");
    r["policy_identifier"] = identifier;

    auto attributes = split(identifier, ":");
    r["policy_attribute"] = attributes.size() == 3 ? attributes.back() : "";

    auto dict = CFArrayGetValueAtIndex((CFArrayRef)content, i);
    const void* description = nullptr;
    if (CFDictionaryGetValueIfPresent((CFDictionaryRef)dict,
                                      CFSTR("policyContentDescription"),
                                      &description) &&
        description != nullptr) {
      r["policy_description"] =
          getPropertiesFromDictionary((CFDictionaryRef)description, "en");
    }
    results.push_back(r);
  }

  CFRelease(policies);

  return results;
}
} // namespace tables
} // namespace osquery
