/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

/**
 * @brief Manages access to SCE RPC client API exported in scecli.dll
 */
class SceClientHelper : public boost::noncopyable {
  /**
   * @brief SCE flag that indicates SCE SYSTEM profile request
   */
  static constexpr DWORD kSceSystemFlag = 300;

  /**
   * @brief SCE bitmask flag that indicates ALL security information flags
   */
  static constexpr DWORD kSceAreaAllFlag = 0xFFFFL;

  /**
   * @brief SCE profile array subdata size
   */
  static constexpr DWORD kSceInfoMaxArray = 3;

  /**
   * @brief Name of the DLL containing the SCE RPC Client API
   */
  const std::string kTargetSCEDLL = "scecli.dll";

  /**
   * @brief Name of the SceFreeMemory export function in scecli.dll
   */
  const std::string kSceFreeMemoryFn = "SceFreeMemory";

  /**
   * @brief Name of the SceGetSecurityProfileInfo export function in scecli.dll
   */
  const std::string kSceGetSecProfileInfoFn = "SceGetSecurityProfileInfo";

 public:
  /**
   * @brief Data structure used by the SCE RPC Protocol to return security
   * profile information
   */
  struct SceProfileInfo {
    DWORD Unk0;
    DWORD MinPasswdAge;
    DWORD MaxPasswdAge;
    DWORD MinPasswdLen;
    DWORD PasswdComplexity;
    DWORD PasswdHistSize;
    DWORD LockoutBadCount;
    DWORD ResetLockoutCount;
    DWORD LockoutDuration;
    DWORD ReqLogonChangePasswd;
    DWORD ForceLogoffExpire;
    PWSTR AdministratorName;
    PWSTR GuestName;
    DWORD Unk1;
    DWORD ClearTextPasswd;
    DWORD LsaAllowAnonymousSidLookup;
    PVOID Unk2;
    PVOID Unk3;
    PVOID Unk4;
    PVOID Unk5;
    PVOID Unk6;
    PVOID Unk7;
    PVOID Unk8;
    PVOID Unk9;
    DWORD MaxLogSize[kSceInfoMaxArray];
    DWORD RetentionLog[kSceInfoMaxArray];
    DWORD RetentionLogDays[kSceInfoMaxArray];
    DWORD RestrictAccessGuest[kSceInfoMaxArray];
    DWORD AuditSystemEvents;
    DWORD AuditLogonEvents;
    DWORD AuditObjectsAccess;
    DWORD AuditPrivilegeUse;
    DWORD AuditPolicyChange;
    DWORD AuditAccountManage;
    DWORD AuditProcessTracking;
    DWORD AuditDSAccess;
    DWORD AuditAccountLogon;
    DWORD AuditFull;
    DWORD RegInfoCount;
    PVOID Unk10;
    DWORD EnableAdminAccount;
    DWORD EnableGuestAccount;
  };

 public:
  /**
   * @brief It ensures that SceClientHelper class only has one instance, and
   * provides a global point of access to it.
   *
   * @return Reference to the single global SceClientHelper instance
   */
  static SceClientHelper& instance();

  /**
   * @brief This helper returns the system security profile information.
   * This is achieved by calling the SceGetSecurityProfileInfo() export in
   * scecli.dll. This function talks to the SCE RPC server to obtain the system
   * security profile information.
   *
   * @param profileData The SceGetSecurityProfileInfo() receives a void pointer,
   * which can be initialized to nullptr as no previous allocation is required.
   * This pointer will be pointing to an allocated instance of SceProfileInfo
   * data structure.
   *
   * @return Status of the call to SceGetSecurityProfileInfo()
   */
  Status getSceSecurityProfileInfo(PVOID& profileData);

  /**
   * @brief This helper frees any memory allocated from calling the
   * SceGetSecurityProfileInfo() exported function in scecli.dll. This is
   * achieved by calling the SceFreeMemory() export in scecli.dll.
   *
   * @param profileData The SceFreeMemory() receives a void pointer,
   * which should be pointing to an instance of the SceProfileInfo data
   * structure.
   *
   * @return Status of the call to SceFreeMemory()
   */
  Status releaseSceProfileData(const PVOID& profileData);

  /**
   * @brief This helper determines if current process is running under WoW64 or
   * an Intel64 of x64 processor. WOW64 is the x86 emulator that allows 32-bit
   * Windows-based applications to run seamlessly on 64-bit Windows. This check
   * is done by calling IsWow64Process().
   *
   * @return WoW64 status of the current process
   */
  static Status isWow64Process();

 private:
  /**
   * @brief Internal helper that checks if process can access the memory layout
   * of the SceProfileInfo data structure pointed by profileData.
   *
   * @param profileData This is pointer to an instance of the SceProfileInfo
   * data structure.
   *
   * @return Valid/Invalid status of the SceProfileInfo pointer
   */
  Status isValidSceProfileData(const PVOID& profileData);

  /**
   * @brief Default constructor
   */
  SceClientHelper();

  /**
   * @brief Default destructor that releases allocated resources
   */
  virtual ~SceClientHelper();

  /**
   * @brief This helper initializes function pointers to SceFreeMemory
   * and SceGetSecurityProfileInfo export functions in scecli.dll by performing
   * run-time dynamic linking.
   *
   * @return Status of the run-time dynamic linking process
   */
  Status initialize();

 private:
  /**
   * @brief This is the function prototype of the undocumented
   * SceFreeMemory() function. This prototype has not
   * changed since windows 7.
   */
  using SceFreeMemoryPtr = DWORD(WINAPI*)(PVOID data, DWORD securityArea);

  /**
   * @brief This is the function prototype of the undocumented
   * SceGetSecurityProfileInfo() function. This prototype has not
   * changed since windows 7.
   */
  using GetSecProfileInfoFnPtr = DWORD(WINAPI*)(PVOID profileHandle,
                                                DWORD type,
                                                DWORD securityArea,
                                                PVOID profileInfo,
                                                PVOID errorInfo);

  /**
   * @brief This handle holds the module reference to scecli.dll
   */
  HMODULE handleSceDLL_{nullptr};

  /**
   * @brief This function pointer points to exported SceFreeMemory in
   * memory.
   */
  SceFreeMemoryPtr sceFreeMemory_{nullptr};

  /**
   * @brief This function pointer points to exported SceGetSecurityProfileInfo
   * in memory.
   */
  GetSecProfileInfoFnPtr sceGetSecurityProfileInfo_{nullptr};

  std::atomic<bool> initialized_{false};
};

/**
 * @brief Scoped management of the security profile memory information
 * returned by the SCE RPC Server
 */
struct SceProfileData {
  /**
   * @brief This helper returns a pointer to the SceProfileInfo data in memory,
   * obtained from calling SceGetSecurityProfileInfo().
   *
   * @return pointer to SceProfileInfo data
   */
  const SceClientHelper::SceProfileInfo* getProfileInfo();

  /**
   * @brief Default destructor in charge of performing RAII scoped data
   * management and freeing allocated memory by calling SceFreeMemory()
   */
  ~SceProfileData();

  /**
   * @brief The SCE RPC protocol IDL uses DWORDs to transport integer values.
   * There are policies on the SCE protocol that uses -1 as a way to indicate
   * maximum value. This helper mimics the secedit binary behavior and
   * normalizes the negative integer data representation in memory of password
   * policy fields to be -1 when representing a negative integer value.
   *
   * @return normalized negative integer
   */
  static int getNormalizedInt(const DWORD& input);

 private:
  PVOID data_{nullptr};
};

} // namespace tables
} // namespace osquery
