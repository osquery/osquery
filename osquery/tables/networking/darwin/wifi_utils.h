/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
