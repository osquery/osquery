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

#include <osquery/dispatcher.h>
#include <osquery/filesystem.h>

namespace osquery {

class Carver : public InternalRunnable {
 public:
  Carver(const std::set<std::string>& paths, const std::string& guid);
  ~Carver();
  void start();

 protected:
  /*
   * @brief A helper function to 'carve' files from disk
   *
   * This function performs a "forensic carve" of a specified path to the
   * users tmp directory
   */
  Status carve(const boost::filesystem::path& path);
  /*
   * @brief A helper function to compress files in a specified directory
   *
   * Given a set of paths we bundle these into a tar archive. This file
   * will be a tgz, however currently no compression is performed.
   */
  Status compress(const std::set<boost::filesystem::path>& path);

  /*
   * @brief Helper function to exfil a file to the graph endpoint.
   *
   * Once all of the files have been carved and the tgz has been
   * created, we POST the carved file to an endpoint specified by the
   * carver_start_endpoint and carver_continue_endpoint
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

 private:
  friend class CarverClass;
};
}
