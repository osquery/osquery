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
#include <string_view>
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
                               size_t occurrences);

/**
 * @brief Split a given string_view based on a delimiter
 *
 * This is at least 2x faster than osquery::split,
 * especially when you only need some of the elements.
 *
 * @param source
 * @param delimiter
 * @return std::vector<std::string_view>
 */
std::vector<std::string_view> vsplit(const std::string_view source,
                                     char delimiter);

} // namespace osquery
