/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/noncopyable.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

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

 private:
  /**
   * @brief Internal helper that checks if process can access the memory layout
   * of the SceProfileInfo data structure pointed by profileData.
   *
   * @param profileData This is pointer to an instance of the SceProfileInfo
   * data structure.
   *
   * @return It returns true if the memory check is successful.
   */
  bool isValidSceProfileData(const PVOID& profileData);

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
  using SceFreeMemoryPtr = DWORD (*)(PVOID data, DWORD securityArea);

  /**
   * @brief This is the function prototype of the undocumented
   * SceGetSecurityProfileInfo() function. This prototype has not
   * changed since windows 7.
   */
  using GetSecProfileInfoFnPtr = DWORD (*)(PVOID profileHandle,
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

SceClientHelper& SceClientHelper::instance() {
  static SceClientHelper instance;
  return instance;
}

SceClientHelper::SceClientHelper() {}

SceClientHelper::~SceClientHelper() {
  if (handleSceDLL_ != nullptr) {
    if (!FreeLibrary(handleSceDLL_)) {
      LOG(ERROR) << "Failed to free module handle of dll " << kTargetSCEDLL;
    }

    handleSceDLL_ = nullptr;
  }

  if (sceFreeMemory_ != nullptr) {
    sceFreeMemory_ = nullptr;
  }

  if (sceGetSecurityProfileInfo_ != nullptr) {
    sceGetSecurityProfileInfo_ = nullptr;
  }

  initialized_ = false;
}

Status SceClientHelper::initialize() {
  // Checking first if the class is already initialized
  if (initialized_) {
    return Status::success();
  }

  // Checking if the input DLL is already mapped to memory before loading it.
  // If mapped module is not found, LoadLibraryExA() gets called to load the
  // module from system32 folder.
  bool increasedRefCount = false;
  HMODULE dllHandle = GetModuleHandleA(kTargetSCEDLL.c_str());
  if (dllHandle == nullptr) {
    // Library was not there in memory already, so we are loading here it and
    // freeing it on the class destructor
    increasedRefCount = true;
    dllHandle = LoadLibraryExA(
        kTargetSCEDLL.c_str(), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  }

  // An invalid module handle means that the DLL couldn't be loaded
  if (dllHandle == nullptr) {
    return Status::failure(kTargetSCEDLL + " dll couldn't be loaded");
  }

  // Getting the address to exported SceFreeMemory function
  PVOID sceFreeMemoryAddr = GetProcAddress(dllHandle, kSceFreeMemoryFn.c_str());
  if (sceFreeMemoryAddr == nullptr) {
    if (increasedRefCount) {
      FreeLibrary(dllHandle);
    }
    return Status::failure(kSceFreeMemoryFn + " couldn't be loaded");
  }

  // Getting the address to exported SceGetSecurityProfileInfo function
  PVOID sceGetProfileInforAddr =
      GetProcAddress(dllHandle, kSceGetSecProfileInfoFn.c_str());
  if (sceGetProfileInforAddr == nullptr) {
    if (increasedRefCount) {
      FreeLibrary(dllHandle);
    }
    return Status::failure(kSceGetSecProfileInfoFn + " couldn't be loaded");
  }

  // Assigning the address of the exports in memory so they can be called thru
  // function pointers that match the target function prototypes
  sceFreeMemory_ = reinterpret_cast<SceFreeMemoryPtr>(sceFreeMemoryAddr);

  sceGetSecurityProfileInfo_ =
      reinterpret_cast<GetSecProfileInfoFnPtr>(sceGetProfileInforAddr);

  // Assigning the handle to the loaded library if ref counter was increased
  if (increasedRefCount) {
    handleSceDLL_ = dllHandle;
  }

  initialized_ = true;

  return Status::success();
}

bool SceClientHelper::isValidSceProfileData(const PVOID& profileData) {
  // Checking that input pointer is initialized
  if (profileData == nullptr) {
    return false;
  }

  // Checking that input pointer points to an accessible SceProfileInfo layout
  if (IsBadReadPtr(&profileData, sizeof(SceProfileInfo))) {
    return false;
  }

  return true;
}

Status SceClientHelper::releaseSceProfileData(const PVOID& profileData) {
  // initializing the class if this is first run
  Status initStatus = initialize();
  if (!initStatus.ok()) {
    return Status::failure(initStatus.getMessage());
  }

  // Sanity check on input
  if (!isValidSceProfileData(profileData)) {
    return Status::failure("Invalid profile data was provided");
  }

  // Sanity check on function pointer about to be used
  if (sceFreeMemory_ == nullptr) {
    return Status::failure(kSceFreeMemoryFn + " cannot be used");
  }

  // Calling the runtime-linked function and checking return code
  DWORD retCode = sceFreeMemory_(profileData, kSceAreaAllFlag);
  if (retCode != ERROR_SUCCESS) {
    return Status::failure(
        kSceGetSecProfileInfoFn +
        " call failed with error: " + std::to_string(retCode));
  }

  // freeing RPC related data
  LocalFree(profileData);

  return Status::success();
}

Status SceClientHelper::getSceSecurityProfileInfo(PVOID& profileData) {
  // initializing the class if this is first run
  Status initStatus = initialize();
  if (!initStatus.ok()) {
    return Status::failure(initStatus.getMessage());
  }

  // Sanity check on function pointer about to be used
  if (sceGetSecurityProfileInfo_ == nullptr) {
    return Status::failure(kSceGetSecProfileInfoFn + " cannot be used");
  }

  // Calling the runtime-linked function and returning the obtained data
  PVOID workProfileData = nullptr;
  DWORD retCode = sceGetSecurityProfileInfo_(
      nullptr, kSceSystemFlag, kSceAreaAllFlag, &workProfileData, nullptr);

  if (retCode != ERROR_SUCCESS) {
    return Status::failure(
        kSceGetSecProfileInfoFn +
        " call failed with error: " + std::to_string(retCode));
  }

  if (!isValidSceProfileData(workProfileData)) {
    return Status::failure(kSceGetSecProfileInfoFn + " returned invalid data");
  }

  profileData = workProfileData;

  return Status::success();
}

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

 private:
  PVOID data_{nullptr};
};

const SceClientHelper::SceProfileInfo* SceProfileData::getProfileInfo() {
  SceClientHelper::SceProfileInfo* profilePtr = nullptr;

  // Obtaining the security profile information if this is the first-run
  if (data_ == nullptr) {
    // grabing the profile data from SCE API
    auto& sceHelper = SceClientHelper::instance();
    Status secReleaseProfileData = sceHelper.getSceSecurityProfileInfo(data_);
    if (!secReleaseProfileData.ok()) {
      LOG(ERROR) << "Failed to release security profile data: "
                 << secReleaseProfileData.getMessage();
      return profilePtr;
    }
  }

  if (data_ != nullptr) {
    profilePtr = reinterpret_cast<SceClientHelper::SceProfileInfo*>(data_);
  }

  return profilePtr;
}

SceProfileData::~SceProfileData() {
  // Releasing memory allocated by getSceSecurityProfileInfo() call
  if (data_ != nullptr) {
    auto& sceHelper = SceClientHelper::instance();
    Status secReleaseProfileData = sceHelper.releaseSceProfileData(data_);
    if (!secReleaseProfileData.ok()) {
      LOG(ERROR) << "Failed to release security profile data: "
                 << secReleaseProfileData.getMessage();
    }

    data_ = nullptr;
  }
}

QueryData genSecurityProfileInformation(QueryContext& context) {
  QueryData results;

  // Getting system security profile information
  SceProfileData data;
  const SceClientHelper::SceProfileInfo* profileData = data.getProfileInfo();
  if (profileData == nullptr) {
    LOG(ERROR) << "Failed to retrieve security profile information data.";
    return results;
  }

  // And then populating the table with obtained data
  Row seceditRow;
  seceditRow["minimum_password_age"] = INTEGER((int)profileData->MinPasswdAge);
  seceditRow["maximum_password_age"] = INTEGER((int)profileData->MaxPasswdAge);
  seceditRow["minimum_password_length"] =
      INTEGER((int)profileData->MinPasswdLen);
  seceditRow["password_complexity"] =
      INTEGER((int)profileData->PasswdComplexity);
  seceditRow["password_history_size"] =
      INTEGER((int)profileData->PasswdHistSize);
  seceditRow["lockout_bad_count"] = INTEGER((int)profileData->LockoutBadCount);
  seceditRow["logon_to_change_password"] =
      INTEGER((int)profileData->ReqLogonChangePasswd);
  seceditRow["force_logoff_when_expire"] =
      INTEGER((int)profileData->ForceLogoffExpire);
  seceditRow["new_administrator_name"] =
      wstringToString(profileData->AdministratorName);
  seceditRow["new_guest_name"] = wstringToString(profileData->GuestName);
  seceditRow["clear_text_password"] =
      INTEGER((int)profileData->ClearTextPasswd);
  seceditRow["lsa_anonymous_name_lookup"] =
      INTEGER((int)profileData->LsaAllowAnonymousSidLookup);
  seceditRow["enable_admin_account"] =
      INTEGER((int)profileData->EnableAdminAccount);
  seceditRow["enable_guest_account"] =
      INTEGER((int)profileData->EnableGuestAccount);
  seceditRow["audit_system_events"] =
      INTEGER((int)profileData->AuditSystemEvents);
  seceditRow["audit_logon_events"] =
      INTEGER((int)profileData->AuditLogonEvents);
  seceditRow["audit_object_access"] =
      INTEGER((int)profileData->AuditObjectsAccess);
  seceditRow["audit_privilege_use"] =
      INTEGER((int)profileData->AuditPrivilegeUse);
  seceditRow["audit_policy_change"] =
      INTEGER((int)profileData->AuditPolicyChange);
  seceditRow["audit_account_manage"] =
      INTEGER((int)profileData->AuditAccountManage);
  seceditRow["audit_process_tracking"] =
      INTEGER((int)profileData->AuditProcessTracking);
  seceditRow["audit_ds_access"] = INTEGER((int)profileData->AuditDSAccess);
  seceditRow["audit_account_logon"] =
      INTEGER((int)profileData->AuditAccountLogon);

  results.push_back(std::move(seceditRow));

  return results;
}

} // namespace tables
} // namespace osquery
