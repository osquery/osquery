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

#include <boost/filesystem/path.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/utils/status.h>

namespace osquery {

/**
 * @brief Parse a property list on disk into a property tree.
 *
 * @param path the input path to a property list.
 * @param tree the output property tree.
 *
 * @return an instance of Status, indicating success or failure if malformed.
 */
Status parsePlist(const boost::filesystem::path& path,
                  boost::property_tree::ptree& tree);

/**
 * @brief Parse property list content into a property tree.
 *
 * @param content the input string-content of a property list.
 * @param tree the output property tree.
 *
 * @return an instance of Status, indicating success or failure if malformed.
 */
Status parsePlistContent(const std::string& content,
                         boost::property_tree::ptree& tree);

/**
 * @brief Parse property list alias data into a path string.
 *
 * @param data a string container with the raw alias data.
 * @param result a string containing the POSIX path.
 *
 * @return an instance of Status, indicating success or failure.
 */
Status pathFromPlistAliasData(const std::string& data, std::string& result);

} // namespace osquery
