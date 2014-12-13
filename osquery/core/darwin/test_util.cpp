// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>

#include "osquery/core/darwin/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace core {

std::string kDarwinPlistTests = "../../../../tools/tests/";

std::string getPlistContent() {
  std::string content;
  readFile(kDarwinPlistTests + "test.plist", content);
  return content;
}

std::string getALFContent() {
  std::string content;
  readFile(kDarwinPlistTests + "test_alf.plist", content);
  return content;
}

pt::ptree getALFTree() {
  auto content = getALFContent();
  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}

std::string getInfoPlistContent() {
  std::string content;
  readFile(kDarwinPlistTests + "test_info.plist", content);
  return content;
}

std::string getLaunchdContent() {
  std::string content;
  readFile(kDarwinPlistTests + "test_launchd.plist", content);
  return content;
}

pt::ptree getInfoPlistTree() {
  auto content = getInfoPlistContent();
  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}

pt::ptree getLaunchdTree() {
  auto content = getLaunchdContent();
  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}
}
}
