/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreWLAN/CoreWLAN.h>

#include <iomanip>

namespace osquery {
namespace tables {

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
}
}
