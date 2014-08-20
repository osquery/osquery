// Copyright 2004-present Facebook. All Rights Reserved.

#include <map>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

DEFINE_string(config_retriever, "", "config_retriever");
DEFINE_string(config_path, "", "config_path");
DEFINE_string(log_receiver, "", "log_receiver");
DEFINE_string(log_path, "", "log_path");

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = 1;

  std::map<std::string, std::string> string_flags = {
      {"config_retriever", FLAGS_config_retriever},
      {"config_path", FLAGS_config_path},
      {"log_receiver", FLAGS_log_receiver},
      {"log_path", FLAGS_log_path}, };

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
