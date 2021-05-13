/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/system.h>

#include <string>
#include <vector>

namespace osquery {
using ExpectedDecompressData = Expected<std::vector<UCHAR>, ConversionError>;

/**
 * @brief Windows helper function to decompress LZ Xpress Huffman compression
 * data
 *
 * @returns Decompressed data as hex encoded string or error
 */
ExpectedDecompressData decompressLZxpress(std::vector<char> compressed_data,
                                          unsigned long size);
} // namespace osquery