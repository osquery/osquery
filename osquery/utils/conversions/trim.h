/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

namespace osquery
{
/**
 * @brief Remove whitespace either end of a string
 *
 * @param s the string that you'd like to trim
 *
 * @return trimmed string.
 */
std::string trim(const std::string& s);
}