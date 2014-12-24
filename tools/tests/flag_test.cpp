/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

namespace osquery {

DECLARE_string(config_retriever);
DECLARE_string(config_path);
DECLARE_string(log_receiver);
DECLARE_string(osquery_log_dir);

int checkFlags() {
  FLAGS_logtostderr = 1;

  std::map<std::string, std::string> string_flags = {
      {"config_retriever", FLAGS_config_retriever},
      {"config_path", FLAGS_config_path},
      {"log_receiver", FLAGS_log_receiver},
      {"osquery_log_dir", FLAGS_osquery_log_dir},
  };

  int ok = 0;
  for (const auto& it : string_flags) {
    if (it.second == "") {
      LOG(ERROR) << it.first << " not set.";
      ok = 1;
    } else {
      LOG(INFO) << it.first << " is " << it.second;
    }
  }

  return ok;
}
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  return osquery::checkFlags();
}
