/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <csignal>
#include <string>

#include <boost/core/noncopyable.hpp>
#include <osquery/utils/info/tool_type.h>

#include <osquery/core.h>

namespace osquery {

class Status;

/**
 * @brief The requested exit code.
 *
 * Use Initializer::shutdown to request shutdown in most cases.
 * This will raise a signal to the main thread requesting the dispatcher to
 * interrupt all services. There is a thread requesting a join of all services
 * that will continue the shutdown process.
 */
extern volatile std::sig_atomic_t kExitCode;

using ModuleHandle = void*;

/**
 * @brief Getter for a host's current hostname
 *
 * @return a string representing the host's current hostname
 */
std::string getHostname();

/**
 * @brief Getter for a host's fully qualified domain name
 *
 * @return a string representation of the hosts fully qualified domain name
 * if the host is joined to a domain, otherwise it simply returns the hostname
 */
std::string getFqdn();

/**
 * @brief Generate a new generic UUID
 *
 * @return a string containing a random UUID
 */
std::string generateNewUUID();

/**
 * @brief Getter for an instance uuid
 *
 * @return ok on success and ident is set to the instance uuid, otherwise
 * failure.
 */
Status getInstanceUUID(std::string& ident);

/**
 * @brief Getter for an ephemeral uuid
 *
 * @return ok on success and ident is set to the ephemeral uuid, otherwise
 * failure.
 */
Status getEphemeralUUID(std::string& ident);

/**
 * @brief Getter for a host's uuid.
 *
 * @return ok on success and ident is set to the host's uuid, otherwise failure.
 */
Status getHostUUID(std::string& ident);

/**
 * @brief Determine whether the UUID is a placeholder.
 *
 * Some motherboards report placeholder UUIDs which, from point of view of being
 * unique, are useless. This method checks the provided UUID against a list of
 * known placeholders so that it can be treated as invalid. This method ignores
 * case.
 *
 * @param uuid UUID to test.
 * @return true if UUID is a placeholder and false otherwise.
 */
bool isPlaceholderHardwareUUID(const std::string& uuid);

/**
 * @brief generate a uuid to uniquely identify this machine
 *
 * @return uuid string to identify this machine
 */
std::string generateHostUUID();

/**
 * @brief Get a configured UUID/name that uniquely identify this machine
 *
 * @return string to identify this machine
 */
std::string getHostIdentifier();

/**
 * @brief Create a pid file
 *
 * @return A status object indicating the success or failure of the operation
 */
Status createPidFile();

/**
 * @brief Getter for determining Admin status
 *
 * @return A bool indicating if the current process is running as admin
 */
bool isUserAdmin();

/**
 * @brief Set the name of the thread
 *
 * @return If the name was set successfully
 */
Status setThreadName(const std::string& name);

/**
 * @brief Initialize any platform dependent libraries or objects
 *
 * On windows, we require the COM libraries be initialized just once
 */
void platformSetup();

/**
 * @brief Before ending, tear down any platform specific setup
 *
 * On windows, we require the COM libraries be initialized just once
 */
void platformTeardown();

/// Check the program is the osquery daemon.
inline bool isDaemon() {
  return kToolType == ToolType::DAEMON;
}

/// Check the program is the osquery shell.
inline bool isShell() {
  return kToolType == ToolType::SHELL;
}

extern "C" {
/**
 * @brief Check if a process is an osquery worker.
 *
 * By default an osqueryd process will fork/exec then set an environment
 * variable: `OSQUERY_WORKER` while continually monitoring child I/O.
 * The environment variable causes subsequent child processes to skip several
 * initialization steps and jump into extension handling, registry setup,
 * config/logger discovery and then the event publisher and scheduler.
 */
bool isWorker();
}

bool checkPlatform(const std::string& platform);
} // namespace osquery
