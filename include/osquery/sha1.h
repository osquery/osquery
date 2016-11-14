/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

namespace osquery {

/*
 * @brief Request a SHA1 hash from the contents of a buffer.
 *
 * @param buffer A caller-controlled buffer (already allocated).
 * @param size The size of the buffer in bytes.
 * @return A string (hex) representation of the hash digest.
 */
std::string getBufferSHA1(const void* buffer, size_t size);
}
