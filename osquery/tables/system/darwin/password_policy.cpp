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

namespace osquery {
namespace tables {

QueryData genPasswordPolicy(QueryContext& context) {
  QueryData results;

  CFErrorRef error = nullptr;
  // Create a node of type LocalNodes with the default OpenDirectory Session
  auto node = ODNodeCreateWithNodeType(
      kCFAllocatorDefault, kODSessionDefault, kODNodeTypeLocalNodes, &error);
  if (node == nullptr) {
    VLOG(1) << "Error creating an OpenDirectory node";
    return {};
  }

  // Get any policies configured for the node
  // policies here is a CFDcitionary
  // The value of "policyCategoryPasswordContent" key is an array
  // Each element of that array is a CFDictionary with "policyContent",
  // "policyContentDescription", "policyIdentifier" keys Note:
  // `ODNodeCopyAccountPolicies` is the only viable API now, all similar ones
  // have been deprecated
  auto policies = ODNodeCopyAccountPolicies(node, &error);
  if (policies == nullptr) {
    VLOG(1) << "Error getting account policies";
    return {};
  }

  auto count = CFDictionaryGetCount(policies);
  if (count == 0) {
    VLOG(1) << "Empty account policies for the node";
    return {};
  }

  if (!CFDictionaryContainsKey(policies,
                               CFSTR("policyCategoryPasswordContent"))) {
    VLOG(1) << "Account policy does not contain password content";
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
    r["policy_attribute"] = getPropertiesFromDictionary(
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)content, i),
        "policyContent");
    r["policy_identifier"] = getPropertiesFromDictionary(
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)content, i),
        "policyIdentifier");

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