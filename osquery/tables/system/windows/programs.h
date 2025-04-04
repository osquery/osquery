/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
namespace osquery {
namespace tables {

/*
 * @brief Helper Function to convert a registry-encoded GUID into a standard
 * GUID
 *
 * @param a string that contains the encoded guid, e.g.
 * "0D8797326E7E4114DAECB3B66B9CD045"
 * @return a string that contains the decoded guid, e.g.
 * "{237978D0-E7E6-4114-ADCE-3B6BB6C90D54}" or an empty string if the input is
 * invalid (input must be 32 characters long)
 */
std::string decodeMsiRegistryGuid(const std::string& encoded);

} // namespace tables
} // namespace osquery
