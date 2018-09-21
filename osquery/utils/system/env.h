/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <string>
#include <boost/optional.hpp>


namespace osquery {

/// Set the enviroment variable name with value value.
bool setEnvVar(const std::string& name, const std::string& value);

/// Unsets the environment variable specified by name.
bool unsetEnvVar(const std::string& name);

/**
 * @brief Returns the value of the specified environment variable name.
 *
 * If the environment variable does not exist, boost::none is returned.
 */
boost::optional<std::string> getEnvVar(const std::string& name);

} // namespace osquery
