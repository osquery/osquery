/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

// clang-format off
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
// clang-format on

namespace osquery {
namespace tables {

// Clamp a byte length sourced from a target process's PEB (a USHORT, so up
// to 65535) to the size of the destination buffer (in bytes). The clamped
// value is safe to pass as the nSize argument of ReadProcessMemory when
// writing into a buffer of dest_size bytes.
SIZE_T clampPebReadLength(USHORT peb_length, SIZE_T dest_size);

} // namespace tables
} // namespace osquery
