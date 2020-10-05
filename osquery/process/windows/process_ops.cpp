/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/process/windows/process_ops.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

std::string psidToString(PSID sid) {
  LPSTR sidOut = nullptr;
  auto ret = ConvertSidToStringSidA(sid, &sidOut);
  if (ret == 0) {
    VLOG(1) << "ConvertSidToString failed with " << GetLastError();
    return std::string("");
  }
  std::string sidString(sidOut);
  LocalFree(sidOut);
  return sidString;
}

uint32_t getUidFromSid(PSID sid) {
  auto const uid_default = static_cast<uint32_t>(-1);
  LPSTR sidString = nullptr;
  if (ConvertSidToStringSidA(sid, &sidString) == 0) {
    VLOG(1) << "getUidFromSid failed ConvertSidToStringSid error " +
                   std::to_string(GetLastError());
    LocalFree(sidString);
    return uid_default;
  }

  auto toks = osquery::split(sidString, "-");

  if (toks.size() < 1) {
    LocalFree(sidString);
    return uid_default;
  }

  auto uid_exp = tryTo<uint32_t>(toks.at(toks.size() - 1), 10);

  if (uid_exp.isError()) {
    LocalFree(sidString);
    VLOG(1) << "failed to parse PSID " << uid_exp.getError().getMessage();
    return uid_default;
  }

  LocalFree(sidString);
  return uid_exp.take();
}

uint32_t getGidFromSid(PSID sid) {
  auto eUse = SidTypeUnknown;
  DWORD unameSize = 0;
  DWORD domNameSize = 1;

  // LookupAccountSid first gets the size of the username buff required.
  LookupAccountSidW(
      nullptr, sid, nullptr, &unameSize, nullptr, &domNameSize, &eUse);
  std::vector<wchar_t> uname(unameSize);
  std::vector<wchar_t> domName(domNameSize);
  auto accountFound = LookupAccountSidW(nullptr,
                                        sid,
                                        uname.data(),
                                        &unameSize,
                                        domName.data(),
                                        &domNameSize,
                                        &eUse);

  if (accountFound == 0) {
    return static_cast<uint32_t>(-1);
  }
  // USER_INFO_3 struct contains the RID (uid) of our user
  DWORD userInfoLevel = 3;
  LPBYTE userBuff = nullptr;
  auto gid = static_cast<uint32_t>(-1);
  auto ret = NetUserGetInfo(nullptr, uname.data(), userInfoLevel, &userBuff);

  if (ret == NERR_UserNotFound) {
    LPSTR sidString;
    ConvertSidToStringSidA(sid, &sidString);
    auto toks = osquery::split(sidString, "-");
    gid = tryTo<uint32_t>(toks.at(toks.size() - 1), 10).takeOr(gid);
    LocalFree(sidString);

  } else if (ret == NERR_Success) {
    gid = LPUSER_INFO_3(userBuff)->usri3_primary_group_id;
  }

  NetApiBufferFree(userBuff);
  return gid;
}

std::unique_ptr<BYTE[]> getSidFromUsername(std::wstring accountName) {
  if (accountName.empty()) {
    LOG(INFO) << "No account name provided";
    return nullptr;
  }

  // Call LookupAccountNameW() once to retrieve the necessary buffer sizes for
  // the SID (in bytes) and the domain name (in TCHARS):
  DWORD sidBufferSize = 0;
  DWORD domainNameSize = 0;
  auto eSidType = SidTypeUnknown;
  auto ret = LookupAccountNameW(nullptr,
                                accountName.c_str(),
                                nullptr,
                                &sidBufferSize,
                                nullptr,
                                &domainNameSize,
                                &eSidType);

  if (ret == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    LOG(INFO) << "Failed to lookup account name "
              << wstringToString(accountName.c_str()) << " with "
              << GetLastError();
    return nullptr;
  }

  // Allocate buffers for the (binary data) SID and (wide string) domain name:
  auto sidBuffer = std::make_unique<BYTE[]>(sidBufferSize);
  std::vector<wchar_t> domainName(domainNameSize);

  // Call LookupAccountNameW() a second time to actually obtain the SID for the
  // given account name:
  ret = LookupAccountNameW(nullptr,
                           accountName.c_str(),
                           sidBuffer.get(),
                           &sidBufferSize,
                           domainName.data(),
                           &domainNameSize,
                           &eSidType);
  if (ret == 0) {
    LOG(INFO) << "Failed to lookup account name "
              << wstringToString(accountName.c_str()) << " with "
              << GetLastError();
    return nullptr;
  } else if (IsValidSid(sidBuffer.get()) == FALSE) {
    LOG(INFO) << "The SID for " << wstringToString(accountName.c_str())
              << " is invalid.";
  }

  // Implicit move operation. Caller "owns" returned pointer:
  return sidBuffer;
}

DWORD getRidFromSid(PSID sid) {
  BYTE* countPtr = GetSidSubAuthorityCount(sid);
  DWORD indexOfRid = static_cast<DWORD>(*countPtr - 1);
  DWORD* ridPtr = GetSidSubAuthority(sid, indexOfRid);
  return *ridPtr;
}

uint32_t platformGetUid() {
  auto gid_default = static_cast<uint32_t>(-1);
  auto token = INVALID_HANDLE_VALUE;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return gid_default;
  }

  unsigned long nbytes = 0;
  ::GetTokenInformation(token, TokenUser, nullptr, 0, &nbytes);
  if (nbytes == 0) {
    ::CloseHandle(token);
    return gid_default;
  }

  std::vector<char> tu_buffer;
  tu_buffer.assign(nbytes, '\0');

  auto status = ::GetTokenInformation(token,
                                      TokenUser,
                                      tu_buffer.data(),
                                      static_cast<DWORD>(tu_buffer.size()),
                                      &nbytes);
  ::CloseHandle(token);
  if (status == 0) {
    return gid_default;
  }

  auto tu = PTOKEN_USER(tu_buffer.data());
  return getUidFromSid(tu->User.Sid);
}

bool isLauncherProcessDead(PlatformProcess& launcher) {
  unsigned long code = 0;
  if (launcher.nativeHandle() == INVALID_HANDLE_VALUE) {
    return true;
  }

  if (!::GetExitCodeProcess(launcher.nativeHandle(), &code)) {
    LOG(WARNING) << "GetExitCodeProcess did not return a value, error code ("
                 << GetLastError() << ")";
    return false;
  }
  return (code != STILL_ACTIVE);
}

ModuleHandle platformModuleOpen(const std::string& path) {
  return ::LoadLibraryExW(
      stringToWstring(path).c_str(), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

void* platformModuleGetSymbol(ModuleHandle module, const std::string& symbol) {
  return ::GetProcAddress(static_cast<HMODULE>(module), symbol.c_str());
}

std::string platformModuleGetError() {
  return std::string("GetLastError() = " + std::to_string(::GetLastError()));
}

bool platformModuleClose(ModuleHandle module) {
  return (::FreeLibrary(static_cast<HMODULE>(module)) != 0);
}

void setToBackgroundPriority() {
  auto ret =
      SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
  if (ret != TRUE) {
    LOG(WARNING) << "Failed to set background process priority with "
                 << GetLastError();
  }
}

// Helper function to determine if thread is running with admin privilege.
bool isUserAdmin() {
  HANDLE hToken = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    return false;
  }
  TOKEN_ELEVATION Elevation;
  DWORD cbSize = sizeof(TOKEN_ELEVATION);
  if (GetTokenInformation(
          hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize) ==
      0) {
    CloseHandle(hToken);
    return false;
  }
  if (hToken != nullptr) {
    CloseHandle(hToken);
  }
  return Elevation.TokenIsElevated ? true : false;
}

int platformGetPid() {
  return static_cast<int>(GetCurrentProcessId());
}

uint64_t platformGetTid() {
  return GetCurrentThreadId();
}
}
