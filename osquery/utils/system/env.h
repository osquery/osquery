/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <boost/optional.hpp>


namespace osquery {

/// Set the environment variable name with value value.
bool setEnvVar(const std::wstring& name, const std::wstring& value);

/// Unsets the environment variable specified by name.
bool unsetEnvVar(const std::wstring& name);

/**
 * @brief Returns the value of the specified environment variable name.
 *
 * If the environment variable does not exist, boost::none is returned.
 */
boost::optional<std::wstring> getEnvVar(const std::wstring& name);

} // namespace osquery
