/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <linux/audit.h>

#include <set>
#include <map>

// This map must contain exactly the same elements that
// SELinuxEventSubscriber::GetEventSet() returns!
// clang-format off
const std::map<int, std::string> kSELinuxRecordLabels = {
  {AUDIT_USER_AVC, "USER_AVC"},
  {AUDIT_AVC, "AVC"},
  {AUDIT_SELINUX_ERR, "SELINUX_ERR"},
  {AUDIT_AVC_PATH, "AVC_PATH"},
  {AUDIT_MAC_POLICY_LOAD, "MAC_POLICY_LOAD"},
  {AUDIT_MAC_STATUS, "MAC_STATUS"},
  {AUDIT_MAC_CONFIG_CHANGE, "MAC_CONFIG_CHANGE"},
  {AUDIT_MAC_UNLBL_ALLOW, "MAC_UNLBL_ALLOW"},
  {AUDIT_MAC_CIPSOV4_ADD, "MAC_CIPSOV4_ADD"},
  {AUDIT_MAC_CIPSOV4_DEL, "MAC_CIPSOV4_DEL"},
  {AUDIT_MAC_MAP_ADD, "MAC_MAP_ADD"},
  {AUDIT_MAC_MAP_DEL, "MAC_MAP_DEL"},
  {AUDIT_MAC_IPSEC_ADDSA, "MAC_IPSEC_ADDSA"},
  {AUDIT_MAC_IPSEC_DELSA, "MAC_IPSEC_DELSA"},
  {AUDIT_MAC_IPSEC_ADDSPD, "MAC_IPSEC_ADDSPD"},
  {AUDIT_MAC_IPSEC_DELSPD, "MAC_IPSEC_DELSPD"},
  {AUDIT_MAC_IPSEC_EVENT, "MAC_IPSEC_EVENT"},
  {AUDIT_MAC_UNLBL_STCADD, "MAC_UNLBL_STCADD"},
  {AUDIT_MAC_UNLBL_STCDEL, "MAC_UNLBL_STCDEL"}
};
// clang-format on

// Documented events that could not be found in the headers:
// - USER_SELINUX_ERR
// - USER_MAC_POLICY_LOAD
// - USER_ROLE_CHANGE
// - USER_LABEL_EXPORT
const std::set<int> kSELinuxEventList = {
    // This is outside the documented numeric range (1400-1499)
    AUDIT_USER_AVC,

    AUDIT_AVC,
    AUDIT_SELINUX_ERR,
    AUDIT_AVC_PATH,
    AUDIT_MAC_POLICY_LOAD,
    AUDIT_MAC_STATUS,
    AUDIT_MAC_CONFIG_CHANGE,
    AUDIT_MAC_UNLBL_ALLOW,
    AUDIT_MAC_CIPSOV4_ADD,
    AUDIT_MAC_CIPSOV4_DEL,
    AUDIT_MAC_MAP_ADD,
    AUDIT_MAC_MAP_DEL,
    AUDIT_MAC_IPSEC_ADDSA,
    AUDIT_MAC_IPSEC_DELSA,
    AUDIT_MAC_IPSEC_ADDSPD,
    AUDIT_MAC_IPSEC_DELSPD,
    AUDIT_MAC_IPSEC_EVENT,
    AUDIT_MAC_UNLBL_STCADD,
    AUDIT_MAC_UNLBL_STCDEL};
