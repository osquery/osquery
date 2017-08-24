#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

ADD_OSQUERY_LIBRARY(TRUE osquery_registry
  registry.cpp
)

file(GLOB OSQUERY_REGISTRY_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_REGISTRY_TESTS})
