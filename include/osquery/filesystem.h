// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <map>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include "osquery/status.h"

namespace osquery {

/**
 * @brief Read a file from disk.
 *
 * @param path the path of the file that you would like to read
 * @param content a reference to a string which will be populated with the
 * contents of the path indicated by the path parameter
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status readFile(const std::string& path, std::string& content);

/**
 * @brief A helper to check if a path exists on disk or not.
 *
 * @param path the path on disk which you would like to check the existance of
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation. Specifically, the code of the osquery::Status instance
 * will be -1 if no input was supplied, assuming the caller is not aware of how
 * to check path-getter results. The code will be 0 if the path does not exist
 * on disk and 1 if the path does exist on disk.
 */
osquery::Status pathExists(const std::string& path);

/**
 * @brief List all of the files in a specific directory, non-recursively.
 *
 * @param path the path which you would like to list.
 * @param results a non-const reference to a vector which will be populated
 * with the directory listing of the path param, assuming that all operations
 * completed successfully.
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status listFilesInDirectory(const std::string& path,
                                     std::vector<std::string>& results);

/**
 * @brief Parse the content of a tomcat users config file into a ptree
 *
 * @param content A string which represents the content of the file to parse
 * @param tree A non-const reference to a ptree which will be populated with
 * the parsed content
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation
 */
osquery::Status parseTomcatUserConfig(
    const std::string& content,
    std::vector<std::pair<std::string, std::string>>& credentials);

#ifdef __APPLE__
/**
 * @brief Parse a property list on disk into a property tree.
 *
 * @param path the path of the propery list which you'd like to read
 * @param tree a non-const reference to a Boost property tree, which will be
 * populated with the results of the property list
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status parsePlist(const std::string& path,
                           boost::property_tree::ptree& tree);
/**
 * @brief Parse property list content into a property tree.
 *
 * @param fileContent a string reference to the content of a plist
 * @param tree a non-const reference to a Boost property tree, which will be
 * populated with the results of the property list
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status parsePlistContent(const std::string& fileContent,
                                  boost::property_tree::ptree& tree);
#endif
}
