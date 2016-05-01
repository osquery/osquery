/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <thread>
#include <string>

#include <boost/optional.hpp>

#include "osquery/core/process.h"

namespace osquery 
{

void processSleep(unsigned int msec)
{
  std::chrono::milliseconds mduration(msec);
  std::this_thread::sleep_for(mduration);
}

}
