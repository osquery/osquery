/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

/**
 * Copyright 2018 Alex Ionescu. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided
 * that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and
 *    the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions
 *    and the following disclaimer in the documentation and/or other materials
 * provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ALEX IONESCU ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ALEX
 * IONESCU
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and
 * should not be interpreted as representing official policies, either expressed
 * or implied, of Alex Ionescu.
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
