/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <functional>

#include <boost/noncopyable.hpp>
#include <osquery/utils/conversions/tryto.h>
#include <tsk/libtsk.h>

namespace osquery {
using ExpectedFileContent = Expected<bool, ConversionError>;
using ExpectedImage = Expected<bool, ConversionError>;

/**
 * @brief Windows helper function for opening Logical Volume (C:\)
 *
 * @returns Status of opening Volume
 */
ExpectedImage openLogical(const std::string& device_path,
                          std::shared_ptr<TskImgInfo>& image);
/**
 * @brief Windows helper function to read a raw file
 *
 * @returns Status of reading the file
 */
ExpectedFileContent readRawFile(std::shared_ptr<TskImgInfo>& image,
                                const std::string& file_path,
                                std::vector<char>& file_contents);
} // namespace osquery
