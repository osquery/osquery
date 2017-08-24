#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

ADD_OSQUERY_LIBRARY(TRUE osquery_distributed
  distributed.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_distributed_plugins
  plugins/tls_distributed.cpp
)

file(GLOB OSQUERY_DISTRIBUTED_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_DISTRIBUTED_TESTS})
