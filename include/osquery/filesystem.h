/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/status.h>

namespace osquery {

/**
 * @brief Read a file from disk.
 *
 * @param path the path of the file that you would like to read
 * @param content a reference to a string which will be populated with the
 * contents of the path indicated by the path parameter
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation.
 */
Status readFile(const boost::filesystem::path& path, std::string& content);

/**
 * @brief Write text to disk.
 *
 * @param path the path of the file that you would like to write
 * @param content the text that should be written exactly to disk
 * @param permissions the filesystem permissions to request when opening
 * @param force_permissions always chmod the path after opening
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation.
 */
Status writeTextFile(const boost::filesystem::path& path,
                     const std::string& content,
                     int permissions = 0660,
                     bool force_permissions = false);

Status isWritable(const boost::filesystem::path& path);
Status isReadable(const boost::filesystem::path& path);

/**
 * @brief A helper to check if a path exists on disk or not.
 *
 * @param path the path on disk which you would like to check the existence of
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation. Specifically, the code of the Status instance
 * will be -1 if no input was supplied, assuming the caller is not aware of how
 * to check path-getter results. The code will be 0 if the path does not exist
 * on disk and 1 if the path does exist on disk.
 */
Status pathExists(const boost::filesystem::path& path);

/**
 * @brief List all of the files in a specific directory, non-recursively.
 *
 * @param path the path which you would like to list.
 * @param results a non-const reference to a vector which will be populated
 * with the directory listing of the path param, assuming that all operations
 * completed successfully.
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation.
 */
Status listFilesInDirectory(const boost::filesystem::path& path,
                            std::vector<std::string>& results);

/**
 * @brief Get directory portion of a path.
 *
 * @param path The input path, either a filename or directory.
 * @param dirpath a non-const reference to a resultant directory portion.
 *
 * @return If the input path was a directory this will indicate failure. One
 * should use `isDirectory` before.
 */
Status getDirectory(const boost::filesystem::path& path,
                    boost::filesystem::path& dirpath);

/**
 * @brief Check if an input path is a directory.
 *
 * @param path The input path, either a filename or directory.
 *
 * @return If the input path was a directory.
 */
Status isDirectory(const boost::filesystem::path& path);

/**
 * @brief Parse the users out of a tomcat user config from disk
 *
 * @param path A string which represents the path of the tomcat user config
 * @param a vector of pairs which represent all of the users which were found
 * in the supplied file. pair.first is the username and pair.second is the
 * password.
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation
 */
Status parseTomcatUserConfigFromDisk(
    const boost::filesystem::path& path,
    std::vector<std::pair<std::string, std::string> >& credentials);

/**
 * @brief Parse the users out of a tomcat user config
 *
 * @param content A string which represents the content of the file to parse
 * @param a vector of pairs which represent all of the users which were found
 * in the supplied file. pair.first is the username and pair.second is the
 * password.
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation
 */
Status parseTomcatUserConfig(
    const std::string& content,
    std::vector<std::pair<std::string, std::string> >& credentials);

#ifdef __APPLE__
/**
 * @brief Parse a property list on disk into a property tree.
 *
 * @param path the path of the propery list which you'd like to read
 * @param tree a non-const reference to a Boost property tree, which will be
 * populated with the results of the property list
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation.
 */
Status parsePlist(const boost::filesystem::path& path,
                  boost::property_tree::ptree& tree);

/**
 * @brief Parse property list content into a property tree.
 *
 * @param fileContent a string reference to the content of a plist
 * @param tree a non-const reference to a Boost property tree, which will be
 * populated with the results of the property list
 *
 * @return an instance of Status, indicating the success or failure
 * of the operation.
 */
Status parsePlistContent(const std::string& fileContent,
                         boost::property_tree::ptree& tree);
#endif

#ifdef __linux__
/**
 * @brief Iterate over proc process, returns a list of pids.
 *
 * @param processes output list of process pids as strings (int paths in proc).
 *
 * @return status of iteration.
 */
Status procProcesses(std::vector<std::string>& processes);

/**
 * @brief Iterate over a proc process's descriptors, return a list of fds.
 *
 * @param process a string pid from proc.
 * @param descriptors output list of descriptor numbers as strings.
 *
 * @return status of iteration, failure if the process path did not exist.
 */
Status procDescriptors(const std::string& process,
                       std::map<std::string, std::string>& descriptors);

/**
 * @brief Read a descriptor's virtual path.
 *
 * @param process a string pid from proc.
 * @param descriptor a string descriptor number for a proc.
 * @param result output variable with value of link.
 *
 * @return status of read, failure on permission error or filesystem error.
 */
Status procReadDescriptor(const std::string& process,
                          const std::string& descriptor,
                          std::string& result);

/**
 * @brief Read bytes from Linux's raw memory.
 *
 * Most Linux kernels include a device node /dev/mem that allows priviledged
 * users to map or seek/read pages of physical memory.
 * osquery discourages the use of physical memory reads for security and
 * performance reasons and must first try safer methods for data parsing
 * such as /sys and /proc.
 *
 * A platform user may disable physical memory reads:
 *   --disable_memory=true
 * This flag/option will cause readRawMemory to forcefully fail.
 *
 * @param base The absolute memory address to read from. This does not need
 * to be page alined, readRawMem will take care of alignment and only
 * return the requested start address and size.
 * @param length The length of the buffer with a max of 0x10000.
 * @param buffer The output buffer, caller is responsible for resources if
 * readRawMem returns success.
 * @return status The status of the read.
 */
Status readRawMem(size_t base, size_t length, void** buffer);

#endif
}
