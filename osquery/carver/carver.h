/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/status/status.h>

#include <atomic>
#include <set>
#include <string>

namespace osquery {

class CarverRunnable : public InternalRunnable {
 public:
  CarverRunnable() : InternalRunnable("CarverRunnable") {
    running_ = true;
  }

  ~CarverRunnable() {
    running_ = false;
  }

  /// Scan all carve requests and carve them serially.
  void start() override;

  virtual Status doCarve(const std::set<std::string>& paths,
                         const std::string& guid,
                         const std::string& requestId) = 0;

  /// Check if a carver runner exists.
  static bool running() {
    return running_;
  }

 private:
  /**
   * @brief Static state to check if a Carver runner is dispatched.
   *
   * Expect that a carver runner will run as long as there are pending carves.
   * Afterwards it will end and need to be dispatched again.
   */
  static std::atomic<bool> running_;
};

template <typename T>
class CarverRunner : public CarverRunnable {
 public:
  CarverRunner() : CarverRunnable() {}

  /**
   * @brief The entry point to creating and calling the Carver.
   *
   * This is implemented to allow faking the carver within tests.
   */
  Status doCarve(const std::set<std::string>& paths,
                 const std::string& guid,
                 const std::string& requestId) override {
    carves_++;
    T carve(paths, guid, requestId);
    return carve.carve();
  }

  /**
   * @brief A helper function to inspect the number of carves attempted.
   *
   * This is not the "total number" of carves, since this carver runner is
   * ephemeral. Once this runner is finished executing the requested carves it
   * will end. The next runner will reset the count of carves at 0.
   */
  size_t carves() {
    return carves_;
  }

 private:
  /// Count the number of carves.
  size_t carves_{0};
};

class Carver {
 public:
  Carver(const std::set<std::string>& paths,
         const std::string& guid,
         const std::string& requestId);

  virtual ~Carver();

  /**
   * @brief A helper function to perform a start to finish carve.
   *
   * This function walks through the carve, compress, and post functions
   * in one fell swoop. Use of this class should largely happen through
   * this function.
   */
  Status carve();

  /// Create the archive and compression paths.
  Status createPaths();

 protected:
  /**
   * @brief A helper function that 'carves' all files from disk.
   *
   * This function copies all source files to a temporary directory and returns
   * a list of all destination files.
   */
  std::set<boost::filesystem::path> carveAll();

  /**
   * @brief A helper function that does a blockwise copy from src to dst.
   *
   * This function copies the source file to the destination file, doing so
   * by blocks specified with FLAGS_carver_block_size (defaults to 8K).
   */
  Status blockwiseCopy(PlatformFile& src, PlatformFile& dst);

  /**
   * @brief Helper function to POST a carve to the graph endpoint.
   *
   * Once all of the files have been carved and the tgz has been
   * created, we POST the carved file to an endpoint specified by the
   * carver_start_endpoint and carver_continue_endpoint.
   */
  virtual Status postCarve(const boost::filesystem::path& path);

  /// Helper function to return the carve directory.
  boost::filesystem::path getCarveDir() {
    return carveDir_;
  }

 protected:
  /**
   * @brief a variable to keep track of the temp path used in carving.
   *
   * This variable represents the location in which we store all of our carved
   * files. When a carve has completed all of the desired files, as well
   * as the tar archive should reside in this directory.
   */
  boost::filesystem::path carveDir_;

  /**
   * @brief a variable tracking all of the paths we attempt to carve.
   *
   * This is a globbed set of file paths that we're expecting will be
   * carved.
   */
  std::set<boost::filesystem::path> carvePaths_;

  /**
   * @brief a helper variable for keeping track of the posix tar archive.
   *
   * This variable is the absolute location of the tar archive created from
   * tar'ing all of the carved files from the carve temp dir.
   */
  boost::filesystem::path archivePath_;

  /**
   * @brief a helper variable for keeping track of the compressed tar.
   *
   * This variable is the absolute location of the tar archive created from
   * zstd of the archive.
   */
  boost::filesystem::path compressPath_;

  /**
   * @brief a unique ID identifying the 'carve'.
   *
   * This unique generated GUID is used to identify the carve session from
   * other carves. It is also used by our backend service to derive a
   * session key for sending results.
   */
  std::string carveGuid_;

  /**
   * @brief the distributed work ID of a carve.
   *
   * This value should be used by the TLS endpoints where carve data is
   * aggregated, to tie together a distributed query with the carve data.
   */
  std::string requestId_;
};

/**
 * @brief A basic entry point for executing carve requests.
 *
 * This will dispatch the CarverRunner if it is not already running.
 * Expect the scheduler to periodically call this method.
 */
void scheduleCarves();
} // namespace osquery
