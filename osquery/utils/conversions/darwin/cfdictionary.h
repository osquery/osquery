/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "cfdata.h"
#include "cfnumber.h"
#include "cfstring.h"

#include <CoreFoundation/CoreFoundation.h>
#include <cmath>
#include <string>

namespace osquery {

/**
 * @brief Given a key, get the value from CFDictionary as a string
 */
std::string getPropertiesFromDictionary(const CFDictionaryRef& dict,
                                        const std::string& key);
} // namespace osquery
