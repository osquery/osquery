/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <set>

#include <osquery/carver.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>

namespace osquery {

Carver::Carver(const std::set<std::string>& paths){
  for(const auto& p : paths){
    carvePaths_.insert(p);
  }
};

void Carver::start() {
  pauseMilli(1000);
  for(const auto& p : carvePaths_){
    VLOG(1) << "[+] Carving path - " << p;
  }
};

}
