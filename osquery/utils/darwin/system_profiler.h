/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/status/status.h>

#import <Foundation/Foundation.h>

namespace osquery {

/**
 * @brief Retrieve data from the macOS System Profiler/System Information
 * utility.
 *
 * This could be called from within an @autoreleasepool.
 *
 * @param datatype the data type to request (see `system_profiler
 * -listDataTypes`).
 * @param result the NSDictionary pointer for returning results.
 *
 * @return an instance of Status, indicating success or failure.
 */
Status getSystemProfilerReport(const std::string& datatype,
                               NSDictionary*& result);

} // namespace osquery
