/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include <osquery/utils/system/system.h>

#include <LM.h>

namespace osquery {

template <typename T>
class NetApiObjectPtr final {
 public:
  NetApiObjectPtr() noexcept = default;
  NetApiObjectPtr(NetApiObjectPtr<T>&& other) noexcept
      : pointer(std::exchange(other.pointer, nullptr)) {}

  ~NetApiObjectPtr() {
    if (pointer != nullptr) {
      NetApiBufferFree(pointer);
    }
  }

  NetApiObjectPtr& operator=(NetApiObjectPtr<T>&& other) noexcept {
    if (this != &other) {
      pointer = std::exchange(other.pointer, nullptr);
    }

    return *this;
  }

  NetApiObjectPtr(const NetApiObjectPtr<T>&) = delete;
  NetApiObjectPtr& operator=(const NetApiObjectPtr<T>&) = delete;

  T* operator->() {
    return pointer;
  }

  bool operator==(const T* other) const {
    return pointer == other;
  }

  bool operator!=(const T* other) const {
    return pointer != other;
  }

  T** get_new_ptr() {
    // We ensure that the pointer cannot be leaked
    if (pointer != nullptr) {
      NetApiBufferFree(pointer);
      pointer = nullptr;
    }

    return &pointer;
  }

  const T* get() const {
    return pointer;
  }

 private:
  T* pointer{nullptr};
};

using user_info_0_ptr = NetApiObjectPtr<USER_INFO_0>;
using user_info_2_ptr = NetApiObjectPtr<USER_INFO_2>;
using user_info_3_ptr = NetApiObjectPtr<USER_INFO_3>;
using user_info_4_ptr = NetApiObjectPtr<USER_INFO_4>;
using localgroup_users_info_0_ptr = NetApiObjectPtr<LOCALGROUP_USERS_INFO_0>;
using localgroup_info_1_ptr = NetApiObjectPtr<LOCALGROUP_INFO_1>;

/**
 * @brief Windows helper function used by to convert a binary SID struct into
 * a string.
 *
 * @returns string representation of the binary SID struct.
 */
std::string psidToString(PSID sid);

/**
 * @brief Windows helper function to lookup a SID from a username
 *
 * @returns a unique_ptr to a PSID
 */
std::unique_ptr<BYTE[]> getSidFromAccountName(const std::wstring& account_name);

/**
 * @brief Get the relative identifier (RID) from a security identifier (SID).
 *
 * @returns the RID represented as an unsigned long integer.
 */
DWORD getRidFromSid(PSID sid);

std::optional<std::uint32_t> getGidFromUserSid(PSID sid);
std::optional<std::uint32_t> getGidFromUsername(LPCWSTR username);

std::string getGroupSidFromUserSid(PSID sid);
std::string getGroupSidFromUsername(const std::wstring& username);

std::unique_ptr<BYTE[]> getSidFromAccountName(LPCWSTR account_name);
std::string getUserHomeDir(const std::string& sid);
} // namespace osquery
