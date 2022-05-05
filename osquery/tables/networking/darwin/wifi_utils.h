/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreWLAN/CoreWLAN.h>

#include <iomanip>

namespace osquery {
namespace tables {

std::string getPropertiesFromDictionary(const CFDictionaryRef& dict,
                                        const std::string& key);

/// SSIDs have no character set, mirror Apple's representation of them
std::string extractSsid(const CFDataRef& data);

/// Change a constant into a string representing the network encryption type
std::string getSecurityName(const CWSecurity cw);

/// Change a constant into the channel number
int getChannelNumber(const CWChannel* cwc);

/// Change a constant into the channel width
int getChannelWidth(const CWChannel* cwc);

/// Change a constant into the channel band
int getChannelBand(const CWChannel* cwc);

/// Change a constant into the mode name
std::string getInterfaceModeName(const CWInterfaceMode cwim);
} // namespace tables
} // namespace osquery
