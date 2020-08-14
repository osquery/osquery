/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/optional.hpp>
#include <string>
#include <vector>

namespace osquery {

/// Set the environment variable name with value value.
bool setEnvVar(const std::string& name, const std::string& value);

/// Unsets the environment variable specified by name.
bool unsetEnvVar(const std::string& name);

/**
 * @brief Returns the value of the specified environment variable name.
 *
 * If the environment variable does not exist, boost::none is returned.
 */
boost::optional<std::string> getEnvVar(const std::string& name);

#ifdef WINDOWS
/**
 * @brief Returns the input, with any environment variables present expanded.
 *
 * Returns boost::none on failure.
 */
boost::optional<std::string> expandEnvString(const std::string& input);

/**
 * Splits the input into command line arguments, according to the system's
 * rules.
 *
 * Returns boost::none on failure.
 */
boost::optional<std::vector<std::string>> splitArgs(const std::string& args);
#endif

} // namespace osquery
