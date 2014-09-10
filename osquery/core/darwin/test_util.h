// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "osquery/core/test_util.h"

namespace osquery {
namespace core {

// generate test content of a property list
std::string getPlistContent();

// generate test content of com.apple.alf
std::string getALFcontent();

// generate a test ptree of the content returned by getALFContent
boost::property_tree::ptree getALFTree();

// generate test content of an Info.plist file
std::string getInfoPlistContent();

// generate a test ptree of the content returned by getInfoPlistContent
boost::property_tree::ptree getInfoPlistTree();

// generate test content for a LaunchDaemon
std::string getLaunchdContent();

// generate a test ptree of the content returned by getLaunchdContent
boost::property_tree::ptree getLaunchdTree();
}
}
