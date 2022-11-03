/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/security_profile_info_utils.h>

namespace osquery {
namespace tables {

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

  // Sanity check to ensure that function pointers are not initialized if
  // running process is a WoW64 process
  Status wow64Status = isWow64Process();
  if (wow64Status.ok()) {
    return Status::failure("Init failed: " + wow64Status.getMessage());
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
  sceFreeMemory_ = static_cast<SceFreeMemoryPtr>(sceFreeMemoryAddr);

  sceGetSecurityProfileInfo_ =
      static_cast<GetSecProfileInfoFnPtr>(sceGetProfileInforAddr);

  // Assigning the handle to the loaded library if ref counter was increased
  if (increasedRefCount) {
    handleSceDLL_ = dllHandle;
  }

  initialized_ = true;

  return Status::success();
}

Status SceClientHelper::isValidSceProfileData(const PVOID& profileData) {
  // Checking that input pointer is initialized
  if (profileData == nullptr) {
    return Status::failure("profileData is NULL.");
  }

  // Checking that input pointer points to an accessible SceProfileInfo layout
  if (IsBadReadPtr(&profileData, sizeof(SceProfileInfo))) {
    return Status::failure("profileData layout is invalid.");
  }

  return Status::success();
}

Status SceClientHelper::releaseSceProfileData(const PVOID& profileData) {
  // initializing the class if this is first run
  Status initStatus = initialize();
  if (!initStatus.ok()) {
    return Status::failure(initStatus.getMessage());
  }

  // Sanity check on input
  Status sceProfileDataStatus = isValidSceProfileData(profileData);
  if (!sceProfileDataStatus.ok()) {
    return Status::failure(sceProfileDataStatus.getMessage());
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

Status SceClientHelper::isWow64Process() {
  BOOL wow64 = FALSE;
  if ((IsWow64Process(GetCurrentProcess(), &wow64)) && (wow64)) {
    return Status::success();
  }

  return Status::failure("Current process is a WoW64 process.");
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

  // Sanity check on input
  Status sceProfileDataStatus = isValidSceProfileData(workProfileData);
  if (!sceProfileDataStatus.ok()) {
    return Status::failure(
        kSceGetSecProfileInfoFn +
        " returned invalid data: " + sceProfileDataStatus.getMessage());
  }

  profileData = workProfileData;

  return Status::success();
}

const SceClientHelper::SceProfileInfo* SceProfileData::getProfileInfo() {
  SceClientHelper::SceProfileInfo* profilePtr = nullptr;

  // Obtaining the security profile information if this is the first-run
  if (data_ == nullptr) {
    // grabing the profile data from SCE API
    auto& sceHelper = SceClientHelper::instance();
    Status secGetProfileData = sceHelper.getSceSecurityProfileInfo(data_);
    if (!secGetProfileData.ok()) {
      LOG(ERROR) << "Failed to get security profile data: "
                 << secGetProfileData.getMessage();
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

int SceProfileData::getNormalizedInt(const DWORD& input) {
  int workValue = static_cast<int>(input);
  if (workValue < 0) {
    workValue = -1;
  }

  return workValue;
}

} // namespace tables
} // namespace osquery
