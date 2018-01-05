/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  Copyright 2018 Alex Ionescu.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <ntstatus.h>
#define WIN32_NO_STATUS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#define SystemSpeculationControlInformation (SYSTEM_INFORMATION_CLASS)201
typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION {
  struct {
    ULONG BpbEnabled : 1;
    ULONG BpbDisabledSystemPolicy : 1;
    ULONG BpbDisabledNoHardwareSupport : 1;
    ULONG SpecCtrlEnumerated : 1;
    ULONG SpecCmdEnumerated : 1;
    ULONG IbrsPresent : 1;
    ULONG StibpPresent : 1;
    ULONG SmepPresent : 1;
    ULONG Reserved : 24;
  } SpeculationControlFlags;
} SYSTEM_SPECULATION_CONTROL_INFORMATION,
    *PSYSTEM_SPECULATION_CONTROL_INFORMATION;

#define SystemKernelVaShadowInformation (SYSTEM_INFORMATION_CLASS)196
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION {
  struct {
    ULONG KvaShadowEnabled : 1;
    ULONG KvaShadowUserGlobal : 1;
    ULONG KvaShadowPcid : 1;
    ULONG KvaShadowInvpcid : 1;
    ULONG Reserved : 28;
  } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

namespace osquery {
namespace tables {

QueryData genKvaSpeculative(QueryContext& context) {
  Row r;

  SYSTEM_KERNEL_VA_SHADOW_INFORMATION kvaInfo;
  auto ret = NtQuerySystemInformation(
      SystemKernelVaShadowInformation, &kvaInfo, sizeof(kvaInfo), nullptr);

  if (ret == STATUS_INVALID_INFO_CLASS) {
    LOG(ERROR) << "System does not have appropriate patch or might not "
               << "support the required information class";
    return {};
  }
  // x86 Systems without the mitigation active
  if (ret == STATUS_NOT_IMPLEMENTED) {
    LOG(INFO) << "System may not have KVA mitigations active";
    RtlZeroMemory(&kvaInfo, sizeof(kvaInfo));
  } else if (!NT_SUCCESS(ret)) {
    LOG(ERROR) << "Failed to query KVA system information";
    return {};
  }

  r["kva_shadow_enabled"] = INTEGER(kvaInfo.KvaShadowFlags.KvaShadowEnabled);
  r["kva_shadow_user_global"] =
      INTEGER(kvaInfo.KvaShadowFlags.KvaShadowUserGlobal);
  ;
  r["kva_shadow_pcid"] = INTEGER(kvaInfo.KvaShadowFlags.KvaShadowPcid);
  ;
  r["kva_shadow_inv_pcid"] = INTEGER(kvaInfo.KvaShadowFlags.KvaShadowInvpcid);

  SYSTEM_SPECULATION_CONTROL_INFORMATION specInfo;
  ret = NtQuerySystemInformation(SystemSpeculationControlInformation,
                                 &specInfo,
                                 sizeof(specInfo),
                                 nullptr);

  if (ret == STATUS_INVALID_INFO_CLASS) {
    LOG(ERROR) << "System does not have appropriate patch or might not "
               << "support the required information class";
    return {};
  } else if (!NT_SUCCESS(ret)) {
    LOG(ERROR) << "Failed to query speculative control information";
    return {};
  }

  r["bp_mitigations"] = INTEGER(specInfo.SpeculationControlFlags.BpbEnabled);
  r["bp_system_policy_disabled"] =
      INTEGER(specInfo.SpeculationControlFlags.BpbDisabledSystemPolicy);
  r["bp_hardware_supported"] =
      INTEGER(specInfo.SpeculationControlFlags.BpbDisabledNoHardwareSupport);
  r["speculation_control_support"] =
      INTEGER(specInfo.SpeculationControlFlags.SpecCtrlEnumerated);
  r["speculation_command_support"] =
      INTEGER(specInfo.SpeculationControlFlags.SpecCmdEnumerated);
  r["ibrs_speculation_control_enabled"] =
      INTEGER(specInfo.SpeculationControlFlags.IbrsPresent);
  r["sti_bp_enabled"] = INTEGER(specInfo.SpeculationControlFlags.StibpPresent);

  return {r};
}
} // namespace tables
} // namespace osquery
