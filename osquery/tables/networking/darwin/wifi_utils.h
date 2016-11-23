/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <CoreWLAN/CoreWLAN.h>
// SSIDs have no character set associated with them
// mirror Apple's representation of them
std::string extractSsid(const CFDataRef& data);

// Change an Apple Constant into a human readable string representing
// the network encryption type
std::string getSecurityName(CWSecurity cw);

// Change an Apple constant into the channel width
int getChannelWidth(CWChannel* cwc);

// Change an Apple constant into the channel band
int getChannelBand(CWChannel* cwc);

// Change an Apple constant into the mode name
std::string getInterfaceModeName(CWInterfaceMode cwim);
