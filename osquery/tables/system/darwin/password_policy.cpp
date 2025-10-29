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
#include <osquery/sql/sqlite_util.h>
#include <osquery/utils/conversions/darwin/cfdictionary.h>

namespace osquery {
namespace tables {

const std::vector<CFStringRef> kPolicyCategories = {
    (__bridge CFStringRef)kODPolicyCategoryPasswordContent,
    (__bridge CFStringRef)kODPolicyCategoryAuthentication,
    (__bridge CFStringRef)kODPolicyCategoryPasswordChange,
};

void genRowsFromPolicyCategory(const CFDictionaryRef& policies,
                               CFStringRef category_key,
                               QueryData& results,
                               const std::string& uid = "") {
  if (policies == nullptr) {
    return;
  }

  auto count = CFDictionaryGetCount(policies);
  if (count == 0) {
    return;
  }

  if (!CFDictionaryContainsKey(policies, category_key)) {
    return;
  }

  auto content = CFDictionaryGetValue(policies, category_key);
  if (content == nullptr) {
    return;
  }

  count = CFArrayGetCount((CFArrayRef)content);
  for (CFIndex i = 0; i < count; i++) {
    Row r;
    r["uid"] = uid.empty() ? BIGINT(-1) : BIGINT(uid);
    r["policy_category"] = stringFromCFString(category_key);
    r["policy_content"] = getPropertiesFromDictionary(
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)content, i),
        "policyContent");

    auto identifier = getPropertiesFromDictionary(
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)content, i),
        "policyIdentifier");
    r["policy_identifier"] = identifier;

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
}

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
   * policies is a dictionary with optional keys for different policy
   * categories:
   * - `policyCategoryPasswordContent`: password content requirements
   * - `policyCategoryAuthentication`: authentication policies
   * - `policyCategoryPasswordChange`: password change requirements
   *
   * Each category value is an array of policy dictionaries with keys:
   * `policyContent`, `policyContentDescription`, and `policyIdentifier`
   *
   * (From Apple's docs)
   *
   * Note: `ODNodeCopyAccountPolicies` is the only viable API now, which gets
   * any policies configured for the node.
   * Similar API in OpenDirectory has been deprecated.
   */

  // get policies for the node (i.e. the global policy)
  auto policies = ODNodeCopyAccountPolicies(node, &error);
  if (policies != nullptr) {
    for (const auto& category : kPolicyCategories) {
      genRowsFromPolicyCategory(policies, category, results);
    }
    CFRelease(policies);
  }

  // populate `uids` with the contraint if present, otherwise populate with all
  // uids from `users` table
  std::set<std::string> uids;
  if (context.constraints.at("uid").exists(EQUALS)) {
    for (const auto& uid : context.constraints.at("uid").getAll(EQUALS)) {
      uids.insert(uid);
    }
  } else {
    auto users = SQL::selectAllFrom("users");
    for (const auto& user : users) {
      uids.insert(user.at("uid"));
    }
  }

  // iterate over uids, and get policy for the user
  for (const auto& uid : uids) {
    auto uid_string = CFStringCreateWithCString(
        kCFAllocatorDefault, uid.c_str(), CFStringGetSystemEncoding());
    auto query = ODQueryCreateWithNode(kCFAllocatorDefault,
                                       node,
                                       (CFTypeRef)kODRecordTypeUsers,
                                       kODAttributeTypeUniqueID,
                                       kODMatchEqualTo,
                                       uid_string,
                                       nullptr,
                                       0,
                                       nullptr);
    auto records = ODQueryCopyResults(query, false, nullptr);
    if (records != nullptr && CFArrayGetCount(records) > 0) {
      auto user_policy = ODRecordCopyAccountPolicies(
          (ODRecordRef)CFArrayGetValueAtIndex(records, 0), nullptr);
      if (user_policy != nullptr) {
        for (const auto& category : kPolicyCategories) {
          genRowsFromPolicyCategory(user_policy, category, results, uid);
        }
        CFRelease(user_policy);
      }
    }
    CFRelease(records);
    CFRelease(uid_string);
  }

  return results;
}
} // namespace tables
} // namespace osquery
