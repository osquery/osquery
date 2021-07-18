/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

namespace osquery {
namespace tables {

/**
 * @brief The EFI Boot GUID
 *
 * The secureboot variables are stored in under this guid. In string
 * form, it's 8be4df61-93ca-11d2-aa0d-00e098032b8c
 */
const std::string kEFIBootGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const std::wstring kEFIBootGUIDwin = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";

/**
 * @brief The SecureMode variable name
 */
const std::string kEFISecureBootName = "SecureBoot";

/**
 * @brief The SetupMode variable name
 */
const std::string kEFISetupModeName = "SetupMode";
} // namespace tables
} // namespace osquery
