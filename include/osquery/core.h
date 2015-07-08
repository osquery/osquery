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

#ifndef __constructor__
#define __registry_constructor__ __attribute__((constructor(101)))
#define __plugin_constructor__ __attribute__((constructor(102)))
#else
#define __registry_constructor__ __attribute__((__constructor__(101)))
#define __plugin_constructor__ __attribute__((__constructor__(102)))
#endif

/// A configuration error is catastrophic and should exit the watcher.
#define EXIT_CATASTROPHIC 78

namespace osquery {

/**
 * @brief The version of osquery
 */
extern const std::string kVersion;
extern const std::string kSDKVersion;
extern const std::string kSDKPlatform;

/// Use a macro for the sdk/platform literal, symbols available in lib.cpp.
#define OSQUERY_SDK_VERSION STR(OSQUERY_BUILD_SDK_VERSION)
#define OSQUERY_PLATFORM STR(OSQUERY_BUILD_PLATFORM)

/**
 * @brief A helpful tool type to report when logging, print help, or debugging.
 */
enum ToolType {
  OSQUERY_TOOL_UNKNOWN = 0,
  OSQUERY_TOOL_SHELL,
  OSQUERY_TOOL_DAEMON,
  OSQUERY_TOOL_TEST,
  OSQUERY_EXTENSION,
};

/// The osquery tool type for runtime decisions.
extern ToolType kToolType;

class Initializer {
 public:
  /**
   * @brief Sets up various aspects of osquery execution state.
   *
   * osquery needs a few things to happen as soon as the process begins
   * executing. Initializer takes care of setting up the relevant parameters.
   * Initializer should be called in an executable's `main()` function.
   *
   * @param argc the number of elements in argv
   * @param argv the command-line arguments passed to `main()`
   * @param tool the type of osquery main (daemon, shell, test, extension).
   */
  Initializer(int& argc, char**& argv, ToolType tool = OSQUERY_TOOL_TEST);

  /**
   * @brief Sets up the process as an osquery daemon.
   *
   * A daemon has additional constraints, it can use a process mutex, check
   * for sane/non-default configurations, etc.
   */
  void initDaemon();

  /**
   * @brief Daemon tools may want to continually spawn worker processes
   * and monitor their utilization.
   *
   * A daemon may call initWorkerWatcher to begin watching child daemon
   * processes until it-itself is unscheduled. The basic guarantee is that only
   * workers will return from the function.
   *
   * The worker-watcher will implement performance bounds on CPU utilization
   * and memory, as well as check for zombie/defunct workers and respawn them
   * if appropriate. The appropriateness is determined from heuristics around
   * how the worker exited. Various exit states and velocities may cause the
   * watcher to resign.
   *
   * @param name The name of the worker process.
   */
  void initWorkerWatcher(const std::string& name);

  /// Assume initialization finished, start work.
  void start();
  /// Turns off various aspects of osquery such as event loops.
  void shutdown();

  /**
   * @brief Check if a process is an osquery worker.
   *
   * By default an osqueryd process will fork/exec then set an environment
   * variable: `OSQUERY_WORKER` while continually monitoring child I/O.
   * The environment variable causes subsequent child processes to skip several
   * initialization steps and jump into extension handling, registry setup,
   * config/logger discovery and then the event publisher and scheduler.
   */
  static bool isWorker();

 private:
  /// Initialize this process as an osquery daemon worker.
  void initWorker(const std::string& name);
  /// Initialize the osquery watcher, optionally spawn a worker.
  void initWatcher();
  /// Set and wait for an active plugin optionally broadcasted.
  void initActivePlugin(const std::string& type, const std::string& name);

 private:
  int* argc_;
  char*** argv_;
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
                               const std::string& delim,
                               size_t occurences);

/**
 * @brief In-line replace all instances of from with to.
 *
 * @param str The input/output mutable string.
 * @param from Search string
 * @param to Replace string
 */
inline void replaceAll(std::string& str,
                       const std::string& from,
                       const std::string& to) {
  if (from.empty()) {
    return;
  }

  size_t start_pos = 0;
  while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length();
  }
}

/**
 * @brief Join a vector of strings using a tokenizer.
 *
 * @param s the string that you'd like to split.
 * @param tok a token glue.
 *
 * @return a joined string.
 */
std::string join(const std::vector<std::string>& s, const std::string& tok);

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
 * @brief Getter for the current UNIX time.
 *
 * @return an int representing the amount of seconds since the UNIX epoch
 */
int getUnixTime();

/**
 * @brief In-line helper function for use with utf8StringSize
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
