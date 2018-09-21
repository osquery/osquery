/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <string>
#include <vector>

namespace osquery {

/**
 * @brief Split a given string based on an optional delimiter.
 *
 * If no delimiter is supplied, the string will be split based on whitespace.
 *
 * @param s the string that you'd like to split
 * @param delim the delimiter which you'd like to split the string by
 *
 * @return a vector of strings split by delim.
 */
std::vector<std::string> split(const std::string& s,
                               const std::string& delim = "\t ");

/**
 * @brief Split a given string based on an delimiter.
 *
 * @param s the string that you'd like to split.
 * @param delim the delimiter which you'd like to split the string by.
 * @param occurrences the number of times to split by delim.
 *
 * @return a vector of strings split by delim for occurrences.
 */
std::vector<std::string> split(const std::string& s,
                               char delim,
                               size_t occurences);

}
