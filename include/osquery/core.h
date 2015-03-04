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

#include <string>
#include <vector>

#include <osquery/status.h>

// clang-format off
#ifndef STR
#define STR_OF(x) #x
#define STR(x) STR_OF(x)
#endif
#define STR_EX(x) x
#define CONCAT(x, y) STR(STR_EX(x)STR_EX(y))

#ifndef FRIEND_TEST
#define FRIEND_TEST(test_case_name, test_name) \
  friend class test_case_name##_##test_name##_Test
#endif
// clang-format on

#define EXIT_CATASTROPHIC 9001

namespace osquery {

/**
 * @brief The version of osquery
 */
extern const std::string kVersion;
extern const std::string kSDKVersion;

/// Use a macro for the version literal, set the kVersion symbol in the library.
#define OSQUERY_VERSION STR(OSQUERY_BUILD_VERSION)
#define OSQUERY_SDK_VERSION STR(OSQUERY_BUILD_SDK_VERSION)

/**
 * @brief A helpful tool type to report when logging, print help, or debugging.
 */
enum osqueryTool {
  OSQUERY_TOOL_SHELL,
  OSQUERY_TOOL_DAEMON,
  OSQUERY_TOOL_TEST,
  OSQUERY_EXTENSION,
};

class Initializer {
 public:
  /**
   * @brief Sets up various aspects of osquery execution state.
   *
   * osquery needs a few things to happen as soon as the executable begins
   * executing. initOsquery takes care of setting up the relevant parameters.
   * initOsquery should be called in an executable's `main()` function.
   *
   * @param argc the number of elements in argv
   * @param argv the command-line arguments passed to `main()`
   */
  Initializer(int argc, char* argv[], int tool = OSQUERY_TOOL_TEST);

  /**
   * @brief Sets up the process as an osquery daemon.
   *
   * A daemon has additional constraints, it can use a process mutext, check
   * for sane/non-default configurations, etc.
   */
  void initDaemon();

  /**
   * @brief Daemon tools may want to continually spawn worker processes
   * and monitor their utilization.
   *
   * A daemon may call initWorkerWatcher to begin watching child daemon
   * processes until it-itself is unscheduled. The basic guarentee is that only
   * workers will return from the function.
   *
   * The worker-watcher will implement performance bounds on CPU utilization
   * and memory, as well as check for zombie/defunct workers and respawn them
   * if appropriate. The appropriateness is determined from heuristics around
   * how the worker exitted. Various exit states and velocities may cause the
   * watcher to resign.
   *
   * @param name The name of the worker process.
   */
  void initWorkerWatcher(const std::string& name);

  /// Assume initialization finished, start work.
  void start();
  /// Turns of various aspects of osquery such as event loops.
  void shutdown();
  /// Check if a process is an osquery worker.
  bool isWorker();

 private:
  int argc_;
  char** argv_;
  int tool_;
  std::string binary_;
};

/**
 * @brief Split a given string based on an optional delimiter.
 *
 * If no delimiter is supplied, the string will be split based on whitespace.
 *
 * @param s the string that you'd like to split
 * @param delim the delimiter which you'd like to split the string by
 *
 * @return a vector of strings which represent the split string that you
 * passed as the s parameter.
 */
std::vector<std::string> split(const std::string& s,
                               const std::string& delim = "\t ");

/**
 * @brief Getter for a host's current hostname
 *
 * @return a string representing the host's current hostname
 */
std::string getHostname();

/**
 * @brief generate a uuid to uniquely identify this machine
 *
 * @return uuid string to identify this machine
 */
std::string generateHostUuid();

/**
 * @brief Getter for the current time, in a human-readable format.
 *
 * @return the current date/time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string getAsciiTime();

/**
 * @brief Getter for the current unix time.
 *
 * @return an int representing the amount of seconds since the unix epoch
 */
int getUnixTime();

/**
 * @brief Inline helper function for use with utf8StringSize
 */
template <typename _Iterator1, typename _Iterator2>
inline size_t incUtf8StringIterator(_Iterator1& it, const _Iterator2& last) {
  if (it == last) {
    return 0;
  }

  unsigned char c;
  size_t res = 1;
  for (++it; last != it; ++it, ++res) {
    c = *it;
    if (!(c & 0x80) || ((c & 0xC0) == 0xC0)) {
      break;
    }
  }

  return res;
}

/**
 * @brief Get the length of a UTF-8 string
 *
 * @param str The UTF-8 string
 *
 * @return the length of the string
 */
inline size_t utf8StringSize(const std::string& str) {
  size_t res = 0;
  std::string::const_iterator it = str.begin();
  for (; it != str.end(); incUtf8StringIterator(it, str.end())) {
    res++;
  }

  return res;
}

/**
 * @brief Create a pid file
 *
 * @return A status object indicating the success or failure of the operation
 */
Status createPidFile();
}
