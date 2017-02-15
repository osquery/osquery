/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <set>

#include <osquery/dispatcher.h>
#include <osquery/filesystem.h>

namespace osquery {

class Carver : public InternalRunnable {
 public:
  Carver(const std::set<std::string>& paths);
  ~Carver();
  void start();

 private:
  /*
   * @brief A helper function to 'carve' files from disk
   */
  Status carve(const boost::filesystem::path& path);
  /*
   * @brief A helper function to compress files in a specified directory
   */
  Status compress(const std::set<boost::filesystem::path>& path);

  /*
   * @brief Helper function to exfil a file to the graph endpoint.
   */
  Status exfil(const boost::filesystem::path& path);

 // TODO: Evaluate if we need all of these :P
 private:
  std::set<boost::filesystem::path> carvePaths_;
  boost::filesystem::path archivePath_;
  boost::filesystem::path carveDir_;
  std::string carveGuid_;
  std::string startUri_;
  std::string contUri_;
};
}
