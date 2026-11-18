/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/utils/system/system.h>

#include <evntcons.h>

namespace osquery {

/**
 * @brief Windows helper function that gets the user SID string from the
 * extended header information in an ETW event record.
 *
 * @returns string representation of the user SID.
 */
std::string sidStringFromEtwRecord(const EVENT_RECORD& record);

/**
 * @brief Windows helper function that gets the process image file path from the
 * process ID.
 *
 * @returns string representation of the process image file path.
 */
std::string processImagePathFromProcessId(uint32_t processId);
} // namespace osquery
