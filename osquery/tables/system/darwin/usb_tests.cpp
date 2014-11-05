// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/darwin/test_util.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

using namespace osquery::core;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {


class AppsTests : public testing::Test {};

}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
