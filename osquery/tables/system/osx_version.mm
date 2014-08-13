// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database.h"

#include <string>

#include <boost/lexical_cast.hpp>

#import "NSProcessInfo+PECocoaBackports.h"

using namespace osquery::db;

namespace osquery { namespace tables {

QueryData genOSXVersion() {

  NSOperatingSystemVersion v = [[NSProcessInfo processInfo] operatingSystemVersion];

  Row r;
  r["major"] = boost::lexical_cast<std::string>(v.majorVersion);
  r["minor"] = boost::lexical_cast<std::string>(v.minorVersion);
  r["patch"] = boost::lexical_cast<std::string>(v.patchVersion);

  return {r};
}

}}
