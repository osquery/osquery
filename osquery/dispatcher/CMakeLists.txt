#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

ADD_OSQUERY_LIBRARY(TRUE osquery_dispatcher
  dispatcher.cpp
)

ADD_OSQUERY_TEST(TRUE
  dispatcher/tests/dispatcher_tests.cpp
)

# The following dispatcher ("runner") implementations are additional.
ADD_OSQUERY_LIBRARY(FALSE osquery_dispatcher_runners
  scheduler.cpp
  distributed.cpp
)

ADD_OSQUERY_TEST(FALSE
  dispatcher/tests/scheduler_tests.cpp
)
