/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <csignal>
#include <string>

namespace osquery {

/**
 * @brief The requested exit code.
 *
 * Use requestShutdown to request shutdown in most cases.
 */
int getShutdownExitCode();

/**
 * @brief Set the requested exit code.
 *
 * Use requestShutdown to request shutdown in most cases.
 */
void setShutdownExitCode(int retcode);

/**
 * @brief Wait until a #requestShutdown is issued.
 *
 * The #requestShutdown method is called in a signal handler or service
 * stop event. It may also be called by osquery internal components if an
 * unrecoverable error occurs.
 *
 * This method should be called before Initializer::shutdown.
 */
void waitForShutdown();

/**
 * @brief Check if something has requested a shutdown.
 *
 * This function is not very helpful and should be avoided. It exists to assist
 * tools outside of the daemon such as the shell.
 */
bool shutdownRequested();

/**
 * @brief Forcefully request the application to stop.
 *
 * Since all osquery tools may implement various 'dispatched' services in the
 * form of event handler threads or thrift service and client pools, a stop
 * request should behave nicely and request these services stop.
 *
 * Use shutdown whenever you would normally call stdlib exit.
 *
 * @param retcode the requested return code for the process.
 */
void requestShutdown(int retcode = EXIT_SUCCESS);

/**
 * @brief Forcefully request the application to stop.
 *
 * See #requestShutdown, this overloaded alternative allows the caller to
 * also log a reason/message to the system log. This is intended for extreme
 * failure cases and thus requires an explicit error code.
 *
 * @param retcode the request return code for the process.
 * @param system_log A log line to write to the system's log.
 */
void requestShutdown(int retcode, const std::string& system_log);
} // namespace osquery
